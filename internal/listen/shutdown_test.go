package listen_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"tornato.dev/ggrok/v2/internal/listen"
	"tornato.dev/ggrok/v2/internal/proto"
)

// errClosed stands in for what Accept actually returns once
// their socket has been closed out from under them.
var errClosed = fmt.Errorf("use of closed network connection: %w", net.ErrClosed)

func TestShutdownErr(t *testing.T) {
	t.Parallel()

	canceled := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}

	// buffered mirrors how runTCP declares the channel: cap 1, so the
	// session's send always completes before it cancels ctx.
	buffered := func(errs ...error) chan error {
		ch := make(chan error, 1)
		for _, err := range errs {
			ch <- err
		}
		return ch
	}

	tests := []struct {
		name     string
		ctx      context.Context
		serveErr chan error
		sockErr  error
		want     error
		wantMsg  string
	}{
		{
			// The regression: SIGINT closes the listener, Accept fails, and
			// the session is still parked in a read with nothing to
			// report. Must exit clean, not blame the closed socket.
			name:     "canceled ctx, session silent",
			ctx:      canceled(),
			serveErr: buffered(),
			sockErr:  errClosed,
			want:     context.Canceled,
		},
		{
			// The session gave up and canceled ctx on its way out. It only
			// ever returns over something no redial could fix, so its
			// reason outranks the socket error it caused and needs no
			// dressing up.
			name:     "session unrecoverable",
			ctx:      canceled(),
			serveErr: buffered(proto.ErrPortsMismatch),
			sockErr:  errClosed,
			want:     proto.ErrPortsMismatch,
			wantMsg:  "port count does not match this session's publisher",
		},
		{
			// A session relay deliberately ended explains itself. listen
			// resubscribes rather than stopping over one, so this only
			// reaches ShutdownErr if it happened on the very first attempt.
			name:     "session closed",
			ctx:      canceled(),
			serveErr: buffered(fmt.Errorf("%w: publisher gone", listen.ErrSessionClosed)),
			sockErr:  errClosed,
			want:     listen.ErrSessionClosed,
		},
		{
			// Nothing was canceled, so the socket really did fail on its
			// own - that error is the whole story and must survive.
			name:     "genuine socket failure",
			ctx:      context.Background(),
			serveErr: buffered(),
			sockErr:  errors.New("too many open files"),
			wantMsg:  "accept: too many open files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := listen.ShutdownErr(tt.ctx, tt.serveErr, tt.sockErr, "accept")
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

// TestShutdownErrDoesNotBlock pins the reason serveErr is sampled rather
// than waited on: on a plain SIGINT nothing is ever sent, and blocking for
// it would hang the exit until the session's read deadline elapsed.
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
