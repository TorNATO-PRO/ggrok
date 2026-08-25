// Package listen is the subscriber side of a tunnel: it dials relay, presents
// a session under proto.RoleSubscribe, and binds one local port per port the
// publisher forwards. Every local connection accepted dials a fresh data
// connection to relay, attaches it to the session, and gets spliced to
// whatever share pairs it with - over an encrypted tunnel relay cannot read.
package listen

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/peer"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// ErrSessionClosed reports that relay told this subscriber its session
// has ended - the publisher went away - rather than listen losing relay
// itself. Run returns an error wrapping it, so a caller can tell an
// orderly end of the shared session apart from a broken connection worth
// retrying.
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

	// Token identifies which publisher's session to subscribe to.
	Token proto.Token

	// OnListen, if non-nil, is called once per port with that socket's
	// actual bound address right after it's bound - the requested address
	// if a specific port was asked for, or whatever port the OS actually
	// chose if it was left as 0. Run blocks for the life of the session,
	// so this is the only way a caller finds out which addresses ended up
	// live, and the only way for it to know at all when a port was
	// auto-assigned.
	OnListen func(net.Addr)
}

// Run dials relay, subscribes to Config.Token's session, and forwards
// Config.Addr's local traffic through the tunnel until ctx is canceled or
// an unrecoverable error occurs.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Addr.Len() < 1 {
		return fmt.Errorf("listen: no local address to bind")
	}

	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, false, nil)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	session := peer.NewSession(cfg.Server, tlsConf, cfg.Token, proto.RoleSubscribe)

	control, err := session.DialControl(ctx)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = control.Close() }()

	ports := uint16(cfg.Addr.Len()) //nolint:gosec // hostport.ParseRange bounds a range at MaxPorts

	if err := session.Handshake(control, cfg.Mode, ports); err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, session, control, cfg.Addr, cfg.OnListen)
	default:
		return fmt.Errorf("listen: unsupported mode %v", cfg.Mode)
	}
}

// ShutdownErr explains why a data-plane loop stopped, given the error its
// local socket returned. The socket is closed from under that loop on the
// way out - by the caller canceling ctx, or by the control loop giving up
// and canceling it - so the read/accept error is a symptom of the
// shutdown, never its cause, and reporting it verbatim ("use of closed
// network connection") says nothing true about why we stopped.
//
// controlErr holds the better answer when the control loop is what failed,
// but it's only sampled, never waited on: on a plain SIGINT the control
// loop is still parked in a read with nothing to report, and blocking for
// it would stall the exit until its deadline elapsed.
func ShutdownErr(ctx context.Context, controlErr <-chan error, err error, op string) error {
	select {
	case cErr := <-controlErr:
		return stopReason(cErr)
	default:
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return fmt.Errorf("%s: %w", op, err)
}

// runTCP binds every port in addr and, for each local connection accepted
// on any of them, opens a tunnel tagged with the port it arrived on and
// splices the two together. It runs until ctx is canceled, one of the local
// listeners errors, or the control connection dies.
func runTCP(
	ctx context.Context,
	session peer.Session,
	control *tls.Conn,
	addr hostport.Range,
	onListen func(net.Addr),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	listeners, err := bindRange(ctx, addr)
	if err != nil {
		return err
	}
	defer closeAll(listeners)

	if onListen != nil {
		for _, ln := range listeners {
			onListen(ln.Addr())
		}
	}

	go func() {
		<-ctx.Done()
		closeAll(listeners)
	}()

	controlErr := make(chan error, 1)
	go func() {
		controlErr <- peer.RunControlLoop(ctx, control, handleControl)
		cancel() // relay is gone or hung; stop accepting new local connections
	}()

	// One accept loop per port, each reporting into a channel deep enough
	// to take every one of them: canceling ctx closes all the listeners at
	// once, so they all fail together, and a shallower channel would leave
	// every loop but the first parked on a send forever.
	acceptErr := make(chan error, len(listeners))
	for i, ln := range listeners {
		port := proto.PortIndex(i)
		go func() {
			acceptErr <- acceptLoop(ctx, session, ln, port)
		}()
	}

	// Whichever port fails first ends the whole listen. They share a
	// session, and a subscriber serving some of its range but not the rest
	// is worse than one that stops and says so.
	return ShutdownErr(ctx, controlErr, <-acceptErr, "accept")
}

// handleControl is listen's [peer.ControlHandler]. Apart from
// ControlSessionClosed, nothing listen receives on its control connection
// carries meaning (ControlRequestData is publisher-only) - every other
// frame is just liveness, and what matters is that reading one at all reset
// the deadline for the next.
func handleControl(typ proto.ControlType, payload []byte) error {
	if typ == proto.ControlSessionClosed {
		return sessionClosedErr(payload)
	}

	return nil
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
) error {
	for {
		local, err := ln.Accept()
		if err != nil {
			return err
		}

		go forward(ctx, session, local, port)
	}
}

// forward opens a tunnel for local, tagged with the port it arrived on, and
// splices the two once relay has paired it with the publisher's end.
func forward(ctx context.Context, session peer.Session, local net.Conn, port proto.PortIndex) {
	tunnel, err := session.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachSubscriber, Port: port})
	if err != nil {
		// A local client left connected to a tunnel that never formed would
		// wait on a reply that isn't coming.
		_ = local.Close()
		return
	}

	streamio.Splice(local, tunnel)
}

// stopReason labels why the data plane stopped, given whatever the control
// loop returned. A session relay deliberately closed is already a complete
// explanation of itself; anything else is the control connection failing,
// and should say so.
func stopReason(err error) error {
	if errors.Is(err, ErrSessionClosed) {
		return err
	}

	return fmt.Errorf("control connection: %w", err)
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
