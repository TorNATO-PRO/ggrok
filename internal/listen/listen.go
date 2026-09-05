// Package listen is the subscriber side of a tunnel: it dials relay, presents
// a session under proto.RoleSubscribe, and binds one local port per port the
// publisher forwards. Every local connection accepted dials a fresh data
// connection to relay, attaches it to the session, and gets spliced to
// whatever share pairs it with - over an encrypted tunnel relay cannot read.
package listen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/peer"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// ErrSessionClosed reports that relay told this subscriber its session
// has ended - the publisher went away - rather than listen losing relay
// itself. It reaches a caller through Config.OnDisconnect rather than out
// of Run: a publisher that went away is one of the things listen waits for
// and resubscribes to, so it explains a gap in service rather than the end
// of one.
var ErrSessionClosed = errors.New("session ended")

// Config is the input to Run.
type Config struct {
	// Server is relay's listen address.
	Server hostport.HostPort

	// CertFile, KeyFile, and CAFile identify this listen to relay and
	// verify relay's own certificate, per internal/mtls.
	CertFile, KeyFile, CAFile string

	// Mode is which kind of local service Addr binds.
	Mode proto.Mode

	// Addr is the local address listen binds - one TCP listener per port. It
	// must span as many ports as the session's publisher forwards, though not
	// the same numbers: the two ranges are matched index for index (see
	// proto.PortIndex), and relay turns away a subscriber whose range is a
	// different size.
	Addr hostport.Range

	// Token identifies which publisher's session to subscribe to, and
	// carries the secret sealing its traffic. It is what share hands out;
	// it deliberately cannot publish the session (see proto.SubscriberToken).
	Token proto.SubscriberToken

	// OnListen, if non-nil, is called once per port with that socket's
	// actual bound address right after it's bound - the requested address
	// if a specific port was asked for, or whatever port the OS actually
	// chose if it was left as 0. Run blocks for the life of the session,
	// so this is the only way a caller finds out which addresses ended up
	// live, and the only way for it to know at all when a port was
	// auto-assigned.
	OnListen func(net.Addr)

	// OnDisconnect and OnReconnect, if non-nil, report the session losing
	// relay and getting it back. Run keeps redialing rather than returning
	// on a lost connection - including one relay ended deliberately, which
	// arrives here wrapping ErrSessionClosed - so without these a listen
	// whose publisher has gone is indistinguishable from one nobody is
	// using. The bound ports stay bound throughout either way; what changes
	// is that a connection to them can't be forwarded until the session is
	// back. OnDisconnect is given the error that ended the session and how
	// long until the next attempt.
	OnDisconnect func(err error, retryIn time.Duration)
	OnReconnect  func()
}

// Run subscribes to Config.Token's session and forwards Config.Addr's local
// traffic through the tunnel until ctx is canceled or an unrecoverable
// error occurs. A relay that goes away, or a publisher that does, is waited
// for and resubscribed to rather than reported: see [peer.Session.Serve]
// for what counts as unrecoverable, and Config.OnDisconnect for how to hear
// about the rest.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Addr.Len() < 1 {
		return fmt.Errorf("listen: no local address to bind")
	}

	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, false, nil)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	session := peer.NewSession(cfg.Server, tlsConf, cfg.Token.Credentials(), proto.RoleSubscribe)

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, session, cfg)
	default:
		return fmt.Errorf("listen: unsupported mode %v", cfg.Mode)
	}
}

// ShutdownErr explains why an accept loop stopped, given the error its
// listener returned. The listener is closed from under that loop on the way
// out - by the caller canceling ctx, or by the session giving up and
// canceling it - so the accept error is a symptom of the shutdown, never
// its cause, and reporting it verbatim ("use of closed network connection")
// says nothing true about why we stopped.
//
// serveErr holds the better answer when the session is what ended, and it
// needs no dressing up: it has already outlasted everything a redial could
// fix, so whatever it carries is the reason listen is stopping. It's only
// sampled, never waited on - on a plain SIGINT the session is still parked
// in a read with nothing to report, and blocking for it would stall the
// exit until its deadline elapsed.
func ShutdownErr(ctx context.Context, serveErr <-chan error, err error, op string) error {
	select {
	case sErr := <-serveErr:
		return sErr
	default:
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return fmt.Errorf("%s: %w", op, err)
}

// runTCP binds every port in cfg.Addr and, for each local connection
// accepted on any of them, opens a tunnel tagged with the port it arrived
// on and splices the two together. It runs until ctx is canceled, one of
// the local listeners errors, or the session ends for a reason redialing
// can't fix.
func runTCP(ctx context.Context, session peer.Session, cfg Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The local ports are bound once and held for the life of the process,
	// across however many sessions that spans. Rebinding them per session
	// would hand a port-0 listener a different port every time relay
	// hiccuped, quietly invalidating the address already reported through
	// OnListen - and in the gap it would refuse connections outright, where
	// holding the socket at least lets a client connect and be told.
	listeners, err := bindRange(ctx, cfg.Addr)
	if err != nil {
		return err
	}
	defer closeAll(listeners)

	if cfg.OnListen != nil {
		for _, ln := range listeners {
			cfg.OnListen(ln.Addr())
		}
	}

	go func() {
		<-ctx.Done()
		closeAll(listeners)
	}()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- session.Serve(ctx, peer.ServeConfig{
			Mode:  cfg.Mode,
			Ports: uint16(cfg.Addr.Len()), //nolint:gosec // hostport.ParseRange bounds a range at MaxPorts
			// Nothing listen receives on its control connection carries
			// meaning apart from ControlSessionClosed (ControlRequestData is
			// publisher-only) - every other frame is just liveness, and what
			// matters is that reading one at all reset the deadline for the
			// next.
			Handle: func(typ proto.ControlType, payload []byte) error {
				if typ == proto.ControlSessionClosed {
					return sessionClosedErr(payload)
				}

				return nil
			},
			OnReconnect:  cfg.OnReconnect,
			OnDisconnect: cfg.OnDisconnect,
		})

		cancel() // the session is past saving; stop accepting local connections
	}()

	// One accept loop per port, each reporting into a channel deep enough
	// to take every one of them: canceling ctx closes all the listeners at
	// once, so they all fail together, and a shallower channel would leave
	// every loop but the first parked on a send forever.
	slots := make(chan struct{}, peer.MaxTunnels)
	acceptErr := make(chan error, len(listeners))
	for i, ln := range listeners {
		port := proto.PortIndex(i)
		go func() {
			acceptErr <- acceptLoop(ctx, session, ln, port, slots)
		}()
	}

	// Whichever port fails first ends the whole listen. They share a
	// session, and a subscriber serving some of its range but not the rest
	// is worse than one that stops and says so.
	return ShutdownErr(ctx, serveErr, <-acceptErr, "accept")
}

// bindRange binds a TCP listener on every port in addr, unwinding the ones
// it already bound if any of them fails - a partially bound range is not a
// listen anyone asked for.
func bindRange(ctx context.Context, addr hostport.Range) ([]net.Listener, error) {
	var listenConf net.ListenConfig

	listeners := make([]net.Listener, 0, addr.Len())
	for i := range addr.Len() {
		port, _ := addr.At(i) // i is bounded by Len, so this is always ok

		ln, err := listenConf.Listen(ctx, "tcp", port.String())
		if err != nil {
			closeAll(listeners)
			return nil, fmt.Errorf("listen on %s: %w", port, err)
		}

		listeners = append(listeners, ln)
	}

	return listeners, nil
}

// closeAll closes every listener, ignoring errors - it runs on teardown
// paths where there is nothing left to do about one.
func closeAll(listeners []net.Listener) {
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

// acceptLoop forwards every connection accepted on ln, which is the port
// at index port of the session's range. It returns once ln errors, which
// on an orderly shutdown means it was closed out from under it.
func acceptLoop(
	ctx context.Context,
	session peer.Session,
	ln net.Listener,
	port proto.PortIndex,
	slots chan struct{},
) error {
	for {
		local, err := ln.Accept()
		if err != nil {
			return err
		}

		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				forward(ctx, session, local, port)
			}()
		default:
			_ = local.Close()
		}
	}
}

// forward opens a tunnel for local, tagged with the port it arrived on, and
// splices the two once relay has paired it with the publisher's end.
func forward(ctx context.Context, session peer.Session, local net.Conn, port proto.PortIndex) {
	stop := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer stop()

	tunnel, err := session.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachSubscriber, Port: port})
	if err != nil {
		// A local client left connected to a tunnel that never formed would
		// wait on a reply that isn't coming. This is also what a connection
		// arriving while the session is between relays gets: closed at once,
		// so the client sees a failure it can retry rather than a hang.
		_ = local.Close()
		return
	}

	streamio.Splice(local, tunnel)
}

// sessionClosedErr renders a ControlSessionClosed frame's payload as an
// error wrapping ErrSessionClosed. A payload this build can't parse
// doesn't change the verdict - relay said the session is over either way
// - only how precisely we can report why.
func sessionClosedErr(payload []byte) error {
	reason, err := proto.ReadSessionClosed(payload)
	if err != nil {
		return fmt.Errorf("%w: reason unknown", ErrSessionClosed)
	}

	return fmt.Errorf("%w: %s", ErrSessionClosed, reason)
}
