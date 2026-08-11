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
		return runTCP(ctx, control, tlsConf, cfg.Server, cfg.Addr, cfg.Token)
	case proto.ModeUDP:
		udpSession, err := setupUDPSession(ctx, control, cfg.Server, cfg.Token)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		return runUDP(ctx, control, udpSession, cfg.Addr)
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

	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable:   true,
			Idle:     tcpKeepAliveIdle,
			Interval: tcpKeepAliveInterval,
			Count:    tcpKeepAliveProbeCount,
		})
	}

	if err := proto.WriteConnKind(conn, proto.ConnControl); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

// dialData dials a fresh TCP-mode data connection to relay and writes the
// ConnData discriminator - the first step for every local connection
// listen accepts.
func dialData(ctx context.Context, server hostport.HostPort, tlsConf *tls.Config) (*tls.Conn, error) {
	conn, err := dialTLS(ctx, server, tlsConf)
	if err != nil {
		return nil, err
	}

	if err := proto.WriteConnKind(conn, proto.ConnData); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
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
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var listenConf net.ListenConfig
	ln, err := listenConf.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer func() { _ = ln.Close() }()

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
			select {
			case cErr := <-controlErr:
				return fmt.Errorf("control connection: %w", cErr)
			default:
				return fmt.Errorf("accept: %w", err)
			}
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
// and reads frames off it until ctx is canceled, control errors, or
// relay goes silent for longer than heartbeatSilenceTimeout. listen never
// receives anything meaningful on its control connection beyond
// ControlPong (ControlRequestData is publisher-only), so every frame
// read is just liveness - what matters is that reading one at all resets
// the deadline for the next.
func runControlLoop(ctx context.Context, control *tls.Conn) error {
	stop := make(chan struct{})
	defer close(stop)
	go sendPings(control, stop)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		_ = control.SetReadDeadline(time.Now().Add(heartbeatSilenceTimeout))
		if _, _, err := proto.ReadControlFrame(control); err != nil {
			return fmt.Errorf("read control frame: %w", err)
		}
	}
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
