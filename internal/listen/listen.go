// Package listen is the subscriber side of a TCP/UDP tunnel: it dials
// relay, presents a token under proto.RoleSubscribe, and binds a local
// port. For TCP, every local connection accepted dials a fresh data
// connection to relay, attached to the session by token, and gets
// spliced to whatever share pairs it with; for UDP, every local client's
// datagrams are framed with a FlowID and forwarded the same way.
package listen

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// heartbeatInterval is how often listen sends a ControlPing on its
// control connection to relay. heartbeatSilenceTimeout bounds how long
// listen waits without receiving anything at all before treating relay
// as dead - the same window relay itself uses to notice a dead/hung
// listen, so either side detects the other within a comparable amount of
// time. TCP-level keepalive (see dialControl) catches a severed network
// path; this catches a peer that's still connected but hung.
const (
	heartbeatInterval       = 10 * time.Second
	heartbeatSilenceTimeout = 30 * time.Second
	tcpKeepAliveIdle        = 15 * time.Second
	tcpKeepAliveInterval    = 15 * time.Second
	tcpKeepAliveProbeCount  = 2
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

	// Addr is the local address listen binds - a TCP listener or a UDP
	// socket, per Mode.
	Addr hostport.HostPort

	// Token identifies which publisher's session to subscribe to.
	Token proto.Token

	// OnListen, if non-nil, is called once with the local socket's actual
	// bound address right after Addr is bound - Addr itself if a specific
	// port was requested, or whatever port the OS actually chose if it was
	// left as 0. Run blocks for the life of the session, so this is the
	// only way a caller finds out which address ended up live, and the
	// only way for it to know at all when the port was auto-assigned.
	OnListen func(net.Addr)
}

// Run dials relay, subscribes to Config.Token's session, and forwards
// Config.Addr's local traffic through the tunnel until ctx is canceled or
// an unrecoverable error occurs.
func Run(ctx context.Context, cfg Config) error {
	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, false, nil)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	control, err := dialControl(ctx, cfg.Server, tlsConf)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = control.Close() }()

	if err := proto.Handshake(control, proto.RoleSubscribe, cfg.Mode, cfg.Token); err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, control, tlsConf, cfg.Server, cfg.Addr, cfg.Token, cfg.OnListen)
	case proto.ModeUDP:
		subID, err := readSubscriberID(control)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		quicConn, err := dialUDPConn(ctx, tlsConf, cfg.Server, cfg.Token, subID)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		return runUDP(ctx, control, quicConn, cfg.Addr, cfg.OnListen)
	default:
		return fmt.Errorf("listen: unsupported mode %v", cfg.Mode)
	}
}

// dialControl dials relay over TCP+mTLS, writes the ConnControl
// discriminator, and configures TCP keepalive so a severed network path
// is noticed promptly even before the application-level heartbeat in
// runControlLoop would time out.
func dialControl(ctx context.Context, server hostport.HostPort, tlsConf *tls.Config) (*tls.Conn, error) {
	conn, err := dialTLS(ctx, server, tlsConf)
	if err != nil {
		return nil, err
	}

	setTCPKeepAlive(conn)

	if err := proto.WriteConnKind(conn, proto.ConnControl); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

// dialData dials a fresh TCP-mode data connection to relay and writes the
// ConnData discriminator - the first step for every local connection
// listen accepts. It configures the same TCP keepalive as dialControl:
// a data connection is spliced raw bytes with no application-level
// heartbeat of its own, so without this, a path a NAT/firewall silently
// drops while the tunnel is idle goes unnoticed until the next write.
func dialData(ctx context.Context, server hostport.HostPort, tlsConf *tls.Config) (*tls.Conn, error) {
	conn, err := dialTLS(ctx, server, tlsConf)
	if err != nil {
		return nil, err
	}

	setTCPKeepAlive(conn)

	if err := proto.WriteConnKind(conn, proto.ConnData); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

// setTCPKeepAlive best-effort enables TCP keepalive on conn's underlying
// socket, per tcpKeepAliveIdle/Interval/ProbeCount - a no-op if conn isn't
// backed by a [net.TCPConn].
func setTCPKeepAlive(conn *tls.Conn) {
	tcpConn, ok := conn.NetConn().(*net.TCPConn)
	if !ok {
		return
	}

	_ = tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     tcpKeepAliveIdle,
		Interval: tcpKeepAliveInterval,
		Count:    tcpKeepAliveProbeCount,
	})
}

// dialTLS is the raw dial shared by dialControl and dialData.
func dialTLS(ctx context.Context, server hostport.HostPort, tlsConf *tls.Config) (*tls.Conn, error) {
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsConf}
	conn, err := dialer.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		// tls.Dialer.DialContext always returns a *tls.Conn; unreachable
		// in practice, but fail closed rather than panic on assertion.
		_ = conn.Close()
		return nil, fmt.Errorf("dial %s: unexpected connection type %T", server, conn)
	}

	return tlsConn, nil
}

// runTCP accepts local connections on addr and, for each one, dials a
// fresh data connection to relay, attaches it to token's session, and -
// once relay acks it - splices the two together. It runs until ctx is
// canceled, the local listener errors, or the control connection dies.
func runTCP(
	ctx context.Context,
	control *tls.Conn,
	tlsConf *tls.Config,
	server, addr hostport.HostPort,
	token proto.Token,
	onListen func(net.Addr),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var listenConf net.ListenConfig
	ln, err := listenConf.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer func() { _ = ln.Close() }()

	if onListen != nil {
		onListen(ln.Addr())
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	controlErr := make(chan error, 1)
	go func() {
		err := runControlLoop(ctx, control)
		controlErr <- err
		cancel() // relay is gone or hung; stop accepting new local connections
	}()

	for {
		local, err := ln.Accept()
		if err != nil {
			return ShutdownErr(ctx, controlErr, err, "accept")
		}

		go func() {
			dataConn, err := dialData(ctx, server, tlsConf)
			if err != nil {
				_ = local.Close()
				return
			}

			attach := proto.Attach{Kind: proto.AttachSubscriber, Token: token}
			if attachErr := proto.WriteAttach(dataConn, attach); attachErr != nil {
				_ = dataConn.Close()
				_ = local.Close()
				return
			}

			status, err := proto.ReadAck(dataConn)
			if err != nil || status.Err() != nil {
				_ = dataConn.Close()
				_ = local.Close()
				return
			}

			streamio.Splice(local, dataConn)
		}()
	}
}

// runControlLoop sends a ControlPing on control every heartbeatInterval
// and reads frames off it until ctx is canceled, control errors, relay
// goes silent for longer than heartbeatSilenceTimeout, or relay reports
// the session over. Apart from ControlSessionClosed, nothing listen
// receives here carries meaning (ControlRequestData is publisher-only) -
// every other frame is just liveness, and what matters is that reading
// one at all resets the deadline for the next.
func runControlLoop(ctx context.Context, control *tls.Conn) error {
	stop := make(chan struct{})
	defer close(stop)
	go sendPings(control, stop)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		_ = control.SetReadDeadline(time.Now().Add(heartbeatSilenceTimeout))
		typ, payload, err := proto.ReadControlFrame(control)
		if err != nil {
			return fmt.Errorf("read control frame: %w", err)
		}

		if typ == proto.ControlSessionClosed {
			return sessionClosedErr(payload)
		}
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

// stopReason labels why the data plane stopped, given whatever
// runControlLoop returned. A session relay deliberately closed is already
// a complete explanation of itself; anything else is the control
// connection failing, and should say so.
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

// sendPings writes a ControlPing on control every heartbeatInterval until
// stop is closed. A failed write just ends the pinger silently -
// runControlLoop's own read deadline is what surfaces a dead connection
// as an error.
func sendPings(control *tls.Conn, stop <-chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := proto.WriteControlFrame(control, proto.ControlPing, nil); err != nil {
				return
			}
		}
	}
}
