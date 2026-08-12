package listen_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"tornato.dev/ggrok/v2/internal/listen"
)

// errClosed stands in for what Accept/ReadFromUDP actually return once
// their socket has been closed out from under them.
var errClosed = fmt.Errorf("use of closed network connection: %w", net.ErrClosed)

func TestShutdownErr(t *testing.T) {
	t.Parallel()

	canceled := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}

	// buffered mirrors how runTCP/runUDP declare the channel: cap 1, so the
	// control loop's send always completes before it cancels ctx.
	buffered := func(errs ...error) chan error {
		ch := make(chan error, 1)
		for _, err := range errs {
			ch <- err
		}
		return ch
	}

	tests := []struct {
		name       string
		ctx        context.Context
		controlErr chan error
		sockErr    error
		want       error
		wantMsg    string
	}{
		{
			// The regression: SIGINT closes the listener, Accept fails, and
			// the control loop is still parked in a read with nothing to
			// report. Must exit clean, not blame the closed socket.
			name:       "canceled ctx, control loop silent",
			ctx:        canceled(),
			controlErr: buffered(),
			sockErr:    errClosed,
			want:       context.Canceled,
		},
		{
			// The control loop failed and canceled ctx on its way out. Its
			// reason outranks the socket error it caused.
			name:       "control loop failed",
			ctx:        canceled(),
			controlErr: buffered(errors.New("read control frame: EOF")),
			sockErr:    errClosed,
			wantMsg:    "control connection: read control frame: EOF",
		},
		{
			// A session relay deliberately ended explains itself.
			name:       "session closed",
			ctx:        canceled(),
			controlErr: buffered(fmt.Errorf("%w: publisher gone", listen.ErrSessionClosed)),
			sockErr:    errClosed,
			want:       listen.ErrSessionClosed,
		},
		{
			// Nothing was canceled, so the socket really did fail on its
			// own - that error is the whole story and must survive.
			name:       "genuine socket failure",
			ctx:        context.Background(),
			controlErr: buffered(),
			sockErr:    errors.New("too many open files"),
			wantMsg:    "accept: too many open files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := listen.ShutdownErr(tt.ctx, tt.controlErr, tt.sockErr, "accept")
			if got == nil {
				t.Fatal("listen.ShutdownErr returned nil, want an error")
			}

			if tt.want != nil && !errors.Is(got, tt.want) {
				t.Errorf("listen.ShutdownErr = %v, want it to wrap %v", got, tt.want)
			}
			if tt.wantMsg != "" && got.Error() != tt.wantMsg {
				t.Errorf("listen.ShutdownErr = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

// TestShutdownErrDoesNotBlock pins the reason controlErr is sampled rather
// than waited on: on a plain SIGINT nothing is ever sent, and blocking for
// it would hang the exit until the control loop's read deadline elapsed.
func TestShutdownErrDoesNotBlock(t *testing.T) {
	t.Parallel()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// An open channel no one will ever send on.
		done <- listen.ShutdownErr(ctx, make(chan error), errClosed, "accept")
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("listen.ShutdownErr = %v, want context.Canceled", err)
		}
	case <-t.Context().Done():
		t.Fatal("listen.ShutdownErr blocked waiting on controlErr")
	}
}
