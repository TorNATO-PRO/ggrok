package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
)

// How a dropped session is retried: an exponential backoff from
// reconnectMinDelay, doubling until reconnectMaxDelay, so a relay that
// blipped is picked back up almost immediately while one that's been gone
// for hours is polled at a rate nobody has to think about.
//
// The cap sits deliberately inside relay's own 30s heartbeat timeout. A
// publisher whose connection was severed rather than closed is turned away
// with [proto.ErrPublisherExists] until relay times the dead registration
// out, so the retry has to keep knocking inside that window rather than
// back off past it.
const (
	reconnectMinDelay = 250 * time.Millisecond
	reconnectMaxDelay = 10 * time.Second

	// reconnectMaxShift bounds the doubling, so the shift can't run past
	// the width of a [time.Duration] on a session that's been retrying for
	// a very long time.
	reconnectMaxShift = 8

	// reconnectJitterDiv spreads each delay across the interval ending at
	// it: an attempt waits between 1-1/reconnectJitterDiv and 1 times the
	// delay, so a relay coming back up isn't met by every peer it dropped
	// at the same instant.
	reconnectJitterDiv = 4

	// reconnectStableFor is how long a session has to stay up before the
	// next drop starts over from reconnectMinDelay. Without it, a peer relay
	// accepts and immediately drops would redial at the shortest delay
	// forever.
	reconnectStableFor = time.Minute
)

// ServeConfig is the input to [Session.Serve].
type ServeConfig struct {
	// Mode and Ports are what the session announces in its handshake, and
	// are announced identically on every reconnect: relay pairs peers by
	// their agreed mode and port count, so a session that came back
	// describing itself differently would be a different session.
	Mode  proto.Mode
	Ports uint16

	// Handle receives every control frame relay sends, across every
	// session - it outlives any one connection, so it must not capture one.
	Handle ControlHandler

	// OnReconnect, if non-nil, is called each time a session is
	// re-established. Not for the first one: the caller already knows about
	// that, because Serve returning nothing yet is what says so.
	OnReconnect func()

	// OnDisconnect, if non-nil, is called each time an established session
	// ends and another attempt is scheduled, with the error that ended it
	// and how long the wait will be. A peer whose tunnel has gone quiet
	// otherwise has no way to find out why, since Serve itself doesn't
	// return over anything it can retry.
	OnDisconnect func(err error, retryIn time.Duration)
}

// Serve holds a control connection to relay open for as long as ctx lives,
// dialing a fresh one whenever the current session ends. Every session
// re-announces the same Mode and Ports and reads frames into the same
// Handle, so a caller's data plane spans reconnects without knowing they
// happened - relay hands out a new session, and the tunnels opened against
// it are the same tunnels as before.
//
// The first connection is not retried. It's the caller's answer about
// whether the session is viable at all - an unreachable relay, a token
// nobody is publishing, a port count that doesn't match - and those are
// mistakes to report rather than conditions to wait out. Everything after
// it is retried on the backoff above, so Serve only ever returns because
// ctx ended or because the session cannot be re-established by trying
// again (see [retryable]).
func (s Session) Serve(ctx context.Context, cfg ServeConfig) error {
	var (
		connected bool
		attempt   int
	)

	for {
		control, err := s.connect(ctx, cfg.Mode, cfg.Ports)
		if err == nil {
			if connected && cfg.OnReconnect != nil {
				cfg.OnReconnect()
			}
			connected = true

			started := time.Now()
			err = runSession(ctx, control, cfg.Handle)

			if time.Since(started) >= reconnectStableFor {
				attempt = 0
			}
		}

		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case !connected, !retryable(err):
			return err
		}

		delay := retryDelay(attempt)
		attempt++

		if cfg.OnDisconnect != nil {
			cfg.OnDisconnect(err, delay)
		}

		if err := wait(ctx, delay); err != nil {
			return err
		}
	}
}

// connect opens a control connection and completes its handshake, which is
// the pair of steps that either yields a live session or yields nothing -
// a handshake relay rejects leaves no connection worth keeping.
func (s Session) connect(ctx context.Context, mode proto.Mode, ports uint16) (*tls.Conn, error) {
	control, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stop()

	if err := proto.WriteConnKind(control, proto.ConnControl); err != nil {
		_ = control.Close()
		return nil, err
	}
	if err := proto.Handshake(control, s.role, mode, ports, s.creds); err != nil {
		_ = control.Close()
		return nil, err
	}

	_ = control.SetDeadline(time.Time{})
	return control, nil
}

// runSession runs one connected control loop and closes control on the way
// out. Every session gets a connection of its own, so nothing here outlives
// the one it was handed.
func runSession(ctx context.Context, control *tls.Conn, handle ControlHandler) error {
	defer func() { _ = control.Close() }()

	// Interrupt blocked control I/O as soon as the session is canceled.
	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stop()

	return RunControlLoop(ctx, control, handle)
}

// retryable reports whether a session that ended with err is worth
// redialing for. Nearly everything is: a relay that restarted, a publisher
// that came and went, a token whose session isn't registered yet, a
// connection an intermediary reset.
//
// What isn't is a disagreement the two peers can't settle by trying again.
// A mode or port count that doesn't match the session's publisher means the
// two were started with incompatible arguments, a relay that denied this peer
// will deny the identical peer a second later, and a relay certificate that
// doesn't verify is a trust problem - all of them want a human, and looping
// on them would bury the one message that explains what to fix.
//
// [proto.ErrPublisherExists] is pointedly not in that set: a publisher whose
// connection was severed rather than closed sees it until relay times the
// dead registration out, and giving up there would surrender the session over
// an ordinary flap.
func retryable(err error) bool {
	var certErr *tls.CertificateVerificationError

	switch {
	case errors.Is(err, proto.ErrModeMismatch), errors.Is(err, proto.ErrPortsMismatch):
		return false
	case errors.Is(err, proto.ErrDenied):
		return false
	case errors.As(err, &certErr):
		return false
	default:
		return true
	}
}

// retryDelay is how long to wait before reconnect attempt number attempt,
// counting from zero. See the reconnect constants for the shape of it.
func retryDelay(attempt int) time.Duration {
	delay := reconnectMaxDelay
	if attempt < reconnectMaxShift {
		if doubled := reconnectMinDelay << attempt; doubled < delay {
			delay = doubled
		}
	}

	//nolint:gosec // jitter wants spread between peers, not unpredictability
	return delay - time.Duration(rand.Int64N(int64(delay)/reconnectJitterDiv))
}

// wait blocks for d, or until ctx is done - in which case it reports ctx's
// error, so a peer asked to stop mid-backoff stops then rather than after
// finishing a wait it no longer has a reason to serve.
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
