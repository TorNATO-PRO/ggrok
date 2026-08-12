// Package share is the publisher side of a TCP/UDP tunnel: it dials relay,
// registers a token under proto.RolePublish, and for every stream/flow
// relay hands it, connects to a local service and forwards bytes. relay
// itself never terminates TCP or UDP - it only pairs this connection with
// however many listen subscribers present the matching token.
package share

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

// heartbeatInterval is how often share sends a ControlPing on its control
// connection to relay. heartbeatSilenceTimeout bounds how long share
// waits without receiving anything at all (a ControlPong, or in TCP mode
// a ControlRequestData) before treating relay as dead - the same window
// relay itself uses to notice a dead/hung share, so either side detects
// the other within a comparable amount of time. TCP-level keepalive (see
// dialControl) catches a severed network path; this catches a peer
// that's still connected but hung.
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

	// CertFile, KeyFile, and CAFile identify this share to relay and
	// verify relay's own certificate, per internal/mtls.
	CertFile, KeyFile, CAFile string

	// Mode is which kind of local service Addr names.
	Mode proto.Mode

	// Addr is the local service being forwarded - share dials it fresh
	// for every new stream (TCP) or NAT flow (UDP).
	Addr hostport.HostPort

	// Token scopes which listen subscribers may reach this session.
	Token proto.Token
}

// Run dials relay, registers Config.Token as a publisher, and forwards
// traffic to Config.Addr until ctx is canceled or an unrecoverable error
// occurs.
func Run(ctx context.Context, cfg Config) error {
	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, false, nil)
	if err != nil {
		return fmt.Errorf("share: %w", err)
	}

	control, err := dialControl(ctx, cfg.Server, tlsConf)
	if err != nil {
		return fmt.Errorf("share: %w", err)
	}
	defer func() { _ = control.Close() }()

	if err := proto.Handshake(control, proto.RolePublish, cfg.Mode, cfg.Token); err != nil {
		return fmt.Errorf("share: %w", err)
	}

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, control, tlsConf, cfg.Server, cfg.Addr, cfg.Token)
	case proto.ModeUDP:
		quicConn, err := dialUDPConn(ctx, tlsConf, cfg.Server, cfg.Token)
		if err != nil {
			return fmt.Errorf("share: %w", err)
		}
		return runUDP(ctx, control, quicConn, cfg.Addr)
	default:
		return fmt.Errorf("share: unsupported mode %v", cfg.Mode)
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
// ConnData discriminator - the first step for every connection share
// opens in response to a ControlRequestData. It configures the same TCP
// keepalive as dialControl: a data connection is spliced raw bytes with no
// application-level heartbeat of its own, so without this, a path a
// NAT/firewall silently drops while the tunnel is idle goes unnoticed
// until the next write.
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

// runTCP runs share's TCP-mode data plane: for every ControlRequestData
// relay sends on control, it opens a fresh data connection, attaches it
// to that request, dials the local service, and splices the two
// together. It runs until ctx is canceled or the control connection dies.
func runTCP(
	ctx context.Context,
	control *tls.Conn,
	tlsConf *tls.Config,
	server, addr hostport.HostPort,
	token proto.Token,
) error {
	fulfill := func(reqID uint64) {
		dataConn, err := dialData(ctx, server, tlsConf)
		if err != nil {
			return
		}

		attach := proto.Attach{Kind: proto.AttachPublisher, Token: token, RequestID: reqID}
		if attachErr := proto.WriteAttach(dataConn, attach); attachErr != nil {
			_ = dataConn.Close()
			return
		}

		var dialer net.Dialer
		local, err := dialer.DialContext(ctx, "tcp", addr.String())
		if err != nil {
			_ = dataConn.Close()
			return
		}

		streamio.Splice(dataConn, local)
	}

	return runControlLoop(ctx, control, fulfill)
}

// runControlLoop sends a ControlPing on control every heartbeatInterval
// and reads frames off it until ctx is canceled, control errors, or
// relay goes silent for longer than heartbeatSilenceTimeout. Every
// ControlRequestData frame is dispatched to fulfill in its own goroutine
// so a slow local dial doesn't stall the read loop - and with it, every
// other in-flight request.
func runControlLoop(ctx context.Context, control *tls.Conn, fulfill func(reqID uint64)) error {
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

		if typ == proto.ControlRequestData {
			reqID, err := proto.ReadRequestData(payload)
			if err != nil {
				continue // malformed frame from a misbehaving relay; drop it
			}
			go fulfill(reqID)
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
