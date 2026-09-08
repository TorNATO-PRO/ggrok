package peer_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/peer"
	"tornato.dev/ggrok/v2/internal/proto"
)

// TestRetryable pins which failures Serve waits out and which it reports.
// The distinction is the whole of the reconnect policy: a peer that gives
// up on something temporary strands the tunnel, and one that loops on a
// misconfiguration buries the message explaining what to fix.
func TestRetryable(t *testing.T) {
	t.Parallel()

	certErr := &tls.CertificateVerificationError{
		UnverifiedCertificates: nil,
		Err:                    x509.UnknownAuthorityError{},
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			// The publisher hasn't registered yet, or is itself
			// reconnecting. Waiting is exactly the right move.
			name: "no such session",
			err:  proto.ErrNoSuchSession,
			want: true,
		},
		{
			// A publisher whose connection was severed rather than closed
			// gets this until relay times the dead registration out. It is
			// the case reconnect exists for.
			name: "publisher still registered",
			err:  proto.ErrPublisherExists,
			want: true,
		},
		{
			name: "relay closed the connection",
			err:  fmt.Errorf("read control frame: %w", io.EOF),
			want: true,
		},
		{
			name: "relay rejects client certificate",
			err:  &net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")},
			want: false,
		},
		{
			name: "protocol mismatch",
			err:  peer.ErrProtocolMismatch,
			want: false,
		},
		{
			name: "relay is not listening",
			err:  fmt.Errorf("dial relay: %w", errors.New("connection refused")),
			want: true,
		},
		{
			// Both peers were started with incompatible arguments. Every
			// retry gets the same answer, so report it instead.
			name: "port count mismatch",
			err:  proto.ErrPortsMismatch,
			want: false,
		},
		{
			name: "mode mismatch",
			err:  proto.ErrModeMismatch,
			want: false,
		},
		{
			// Relay presented a certificate this peer's CA doesn't vouch
			// for. A trust problem wants a human, not a loop.
			name: "relay certificate does not verify",
			err:  fmt.Errorf("dial relay: %w", certErr),
			want: false,
		},
		{
			// Relay refused this peer for who it is - a publisher that
			// could not prove the session is its own. A second attempt is
			// the same peer with the same answer waiting, and redialing
			// every ten seconds forever would bury the one line that says
			// the session key is wrong.
			name: "relay denied this peer",
			err:  proto.ErrDenied,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := peer.Retryable(tt.err); got != tt.want {
				t.Errorf("peer.Retryable(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}

// TestRetryDelayBackoff pins the shape of the backoff: every delay lands
// inside its jitter window, the windows grow, and they stop growing at the
// cap rather than running away.
func TestRetryDelayBackoff(t *testing.T) {
	t.Parallel()

	// The lower edge of a delay's jitter window, given the undithered delay
	// it was drawn from.
	floor := func(d time.Duration) time.Duration { return d - d/peer.ReconnectJitterDiv }

	for attempt, want := range []time.Duration{
		peer.ReconnectMinDelay,
		2 * peer.ReconnectMinDelay,
		4 * peer.ReconnectMinDelay,
		8 * peer.ReconnectMinDelay,
	} {
		got := peer.RetryDelay(attempt)
		if got < floor(want) || got > want {
			t.Errorf("peer.RetryDelay(%d) = %s, want within [%s, %s]", attempt, got, floor(want), want)
		}
	}

	// Far enough out that the undithered delay is pinned at the cap. This
	// is the range that matters for correctness rather than taste: relay
	// drops a dead publisher's registration after 30s, and a publisher
	// whose backoff had run past that window would be locked out of its own
	// session for as long as it took to come back around.
	for _, attempt := range []int{8, 12, 64, 1024} {
		got := peer.RetryDelay(attempt)
		if got < floor(peer.ReconnectMaxDelay) || got > peer.ReconnectMaxDelay {
			t.Errorf("peer.RetryDelay(%d) = %s, want within [%s, %s]",
				attempt, got, floor(peer.ReconnectMaxDelay), peer.ReconnectMaxDelay)
		}
	}
}

// TestRetryDelayJitters pins that the delay is actually dithered. Without
// it, every peer relay dropped would come back at the same instant and hand
// it the same thundering herd that knocked it over.
func TestRetryDelayJitters(t *testing.T) {
	t.Parallel()

	const draws = 64

	first := peer.RetryDelay(4)
	for range draws {
		if peer.RetryDelay(4) != first {
			return
		}
	}

	t.Errorf("peer.RetryDelay(4) returned %s on %d consecutive draws, want jitter", first, draws+1)
}

// TestWaitStopsOnCancel pins that a peer asked to stop mid-backoff stops
// then, rather than after finishing a wait it no longer has a reason to
// serve. The cap is 10s, so getting this wrong is a Ctrl+C that appears to
// hang.
func TestWaitStopsOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	start := time.Now()
	if err := peer.Wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("peer.Wait = %v, want context.Canceled", err)
	}

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("peer.Wait took %s to notice a canceled context", elapsed)
	}
}

// TestWaitSleeps pins the other half: an uncanceled wait actually waits,
// so the backoff paces the redials instead of spinning through them.
func TestWaitSleeps(t *testing.T) {
	t.Parallel()

	const nap = 20 * time.Millisecond

	start := time.Now()
	if err := peer.Wait(t.Context(), nap); err != nil {
		t.Fatalf("peer.Wait = %v, want nil", err)
	}

	if elapsed := time.Since(start); elapsed < nap {
		t.Errorf("peer.Wait returned after %s, want at least %s", elapsed, nap)
	}
}

// TestServeFirstAttemptNotRetried pins that the opening connection is the
// caller's answer about whether the session is viable at all. A token
// nobody is publishing is a mistake to report; retrying it forever would
// turn a typo into a hang.
func TestServeFirstAttemptNotRetried(t *testing.T) {
	t.Parallel()

	// A listener that accepts and immediately hangs up stands in for a
	// relay that won't complete a handshake. Whatever error that produces,
	// Serve must return rather than sit in a backoff loop.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	session := newTestSession(t, ln.Addr().String())

	done := make(chan error, 1)
	go func() {
		done <- session.Serve(t.Context(), peer.ServeConfig{
			Mode:         proto.ModeTCP,
			Ports:        1,
			Handle:       func(proto.ControlType, []byte) error { return nil },
			OnReconnect:  nil,
			OnDisconnect: func(error, time.Duration) { t.Error("Serve retried its first attempt") },
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("peer.Session.Serve = nil, want the failure from its first attempt")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer.Session.Serve blocked instead of reporting its first attempt")
	}
}

// newTestSession is a Session pointed at addr with a TLS config that will
// never complete a handshake against it. The tests above only exercise the
// paths before a session is live, where that is enough.
func newTestSession(t *testing.T, addr string) peer.Session {
	t.Helper()

	hp, err := hostport.Parse(addr)
	if err != nil {
		t.Fatalf("parse %s: %v", addr, err)
	}

	key, err := proto.NewSessionKey()
	if err != nil {
		t.Fatalf("new session key: %v", err)
	}

	creds, err := key.Credentials()
	if err != nil {
		t.Fatalf("derive credentials: %v", err)
	}

	return peer.NewSession(hp, &tls.Config{MinVersion: tls.VersionTLS13}, creds, proto.RolePublish)
}
