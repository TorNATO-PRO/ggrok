// Package listen is the subscriber side of a TCP/UDP tunnel: it dials
// relay, presents a token under proto.RoleSubscribe, and binds a local
// port. For TCP, every local connection accepted becomes a new QUIC
// stream bridged to the publisher; for UDP, every local client's
// datagrams are framed with a FlowID and forwarded the same way.
package listen

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// keepAlivePeriod and maxIdleTimeout keep a listen's connection to relay
// alive through long idle stretches between forwarded connections/flows.
// quic-go disables keep-alives by default, which would otherwise let
// MaxIdleTimeout tear down an otherwise-healthy tunnel.
const (
	keepAlivePeriod = 15 * time.Second
	maxIdleTimeout  = 30 * time.Second

	// maxIncomingStreams is raised from quic-go's default of 100 since
	// every local connection accepted becomes a new incoming stream on
	// this connection.
	maxIncomingStreams = 10_000
)

// Config is the input to Run.
type Config struct {
	// Server is relay's QUIC listen address.
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
	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, false)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	quicConf := &quic.Config{
		EnableDatagrams:    cfg.Mode == proto.ModeUDP,
		KeepAlivePeriod:    keepAlivePeriod,
		MaxIdleTimeout:     maxIdleTimeout,
		MaxIncomingStreams: maxIncomingStreams,
	}

	conn, err := quic.DialAddr(ctx, cfg.Server.String(), tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("listen: dial %s: %w", cfg.Server, err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	if err := hello(ctx, conn, cfg.Mode, cfg.Token); err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, conn, cfg.Addr)
	case proto.ModeUDP:
		return runUDP(ctx, conn, cfg.Addr)
	default:
		return fmt.Errorf("listen: unsupported mode %v", cfg.Mode)
	}
}

// hello opens the control stream, subscribes to token's session, and waits
// for relay's ack - so a rejected subscription (no such session, mode
// mismatch) fails immediately instead of a silently dead local listener.
func hello(ctx context.Context, conn *quic.Conn, mode proto.Mode, token proto.Token) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	return proto.Handshake(stream, proto.RoleSubscribe, mode, token)
}

// runTCP accepts local connections on addr and bridges each to a fresh
// stream opened on conn.
func runTCP(ctx context.Context, conn *quic.Conn, addr hostport.HostPort) error {
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

	for {
		local, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}

		go func() {
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				_ = local.Close()
				return
			}

			streamio.Splice(local, stream)
		}()
	}
}
