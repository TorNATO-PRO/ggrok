// Package share is the publisher side of a TCP/UDP tunnel: it dials relay,
// registers a token under proto.RolePublish, and for every stream/flow
// relay hands it, connects to a local service and forwards bytes. relay
// itself never terminates TCP or UDP - it only pairs this connection with
// however many listen subscribers present the matching token.
package share

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

// keepAlivePeriod and maxIdleTimeout keep a share's connection to relay
// alive through long idle stretches between forwarded connections/flows.
// quic-go disables keep-alives by default, which would otherwise let
// MaxIdleTimeout tear down an otherwise-healthy tunnel.
const (
	keepAlivePeriod = 15 * time.Second
	maxIdleTimeout  = 30 * time.Second

	// maxIncomingStreams is raised from quic-go's default of 100 since
	// every subscriber's every forwarded TCP connection becomes a new
	// incoming stream on this connection.
	maxIncomingStreams = 10_000
)

// Config is the input to Run.
type Config struct {
	// Server is relay's QUIC listen address.
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

	quicConf := &quic.Config{
		EnableDatagrams:    cfg.Mode == proto.ModeUDP,
		KeepAlivePeriod:    keepAlivePeriod,
		MaxIdleTimeout:     maxIdleTimeout,
		MaxIncomingStreams: maxIncomingStreams,
	}

	conn, err := quic.DialAddr(ctx, cfg.Server.String(), tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("share: dial %s: %w", cfg.Server, err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	if err := hello(ctx, conn, cfg.Mode, cfg.Token); err != nil {
		return fmt.Errorf("share: %w", err)
	}

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, conn, cfg.Addr)
	case proto.ModeUDP:
		return runUDP(ctx, conn, cfg.Addr)
	default:
		return fmt.Errorf("share: unsupported mode %v", cfg.Mode)
	}
}

// hello opens the control stream, registers as a publisher, and waits for
// relay's ack - so a rejected registration (e.g. token already published)
// fails immediately instead of only surfacing once a subscriber tries to
// use the session.
func hello(ctx context.Context, conn *quic.Conn, mode proto.Mode, token proto.Token) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	return proto.Handshake(stream, proto.RolePublish, mode, token)
}

// runTCP accepts every stream relay opens on this connection - one per
// subscriber-side local connection, from however many subscribers are
// currently attached - and forwards each to a fresh dial of addr.
func runTCP(ctx context.Context, conn *quic.Conn, addr hostport.HostPort) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("accept stream: %w", err)
		}

		go func() {
			var dialer net.Dialer
			local, err := dialer.DialContext(ctx, "tcp", addr.String())
			if err != nil {
				stream.CancelWrite(0)
				stream.CancelRead(0)
				return
			}

			streamio.Splice(stream, local)
		}()
	}
}
