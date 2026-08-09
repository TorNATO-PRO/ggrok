package relay

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/quic-go/quic-go"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/proto"
)

// keepAlivePeriod and maxIdleTimeout keep a connection alive through long
// idle stretches between forwarded connections/flows. quic-go disables
// keep-alives by default, which would otherwise let MaxIdleTimeout tear
// down an otherwise-healthy tunnel.
const (
	keepAlivePeriod = 15 * time.Second
	maxIdleTimeout  = 30 * time.Second

	// maxIncomingStreams is raised from quic-go's default of 100 since
	// relay multiplexes every subscriber's every forwarded TCP
	// connection as a new incoming stream on the publisher's connection.
	maxIncomingStreams = 10_000
)

// Config is the input to Run.
type Config struct {
	// Listen is the address relay's QUIC listener binds to.
	Listen hostport.HostPort

	// CertFile, KeyFile, and CAFile identify relay to its peers and
	// verify their certificates, per internal/mtls.
	CertFile, KeyFile, CAFile string

	// RevokedFile is an optional path to a newline-delimited serial list
	// (see ca.RevokedSerials and the ca crl subcommand). A connecting peer
	// whose certificate serial appears in it is rejected even though its
	// chain still verifies against CAFile - without this, ca revoke is
	// pure bookkeeping, since a revoked cert otherwise keeps authenticating
	// until it naturally expires.
	RevokedFile string
}

// Run listens for QUIC connections on Config.Listen and brokers them
// between share (publisher) and listen (subscriber) peers until ctx is
// canceled.
func Run(ctx context.Context, cfg Config) error {
	revoked, err := loadRevokedSerials(cfg.RevokedFile)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}

	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, true, revoked)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}

	quicConf := &quic.Config{
		EnableDatagrams:    true,
		KeepAlivePeriod:    keepAlivePeriod,
		MaxIdleTimeout:     maxIdleTimeout,
		MaxIncomingStreams: maxIncomingStreams,
	}

	listener, err := quic.ListenAddr(cfg.Listen.String(), tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("relay: listen on %s: %w", cfg.Listen, err)
	}
	defer func() { _ = listener.Close() }()

	registry := NewRegistry()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return fmt.Errorf("relay: accept: %w", err)
		}

		go handleConn(ctx, logger, registry, conn)
	}
}

// loadRevokedSerials reads path via ca.ParseRevokedSerials. An empty path
// is not an error - it just means Run skips revocation checking entirely,
// same as an operator who never ran ca crl.
func loadRevokedSerials(path string) (map[string]struct{}, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open revoked file: %w", err)
	}
	defer func() { _ = f.Close() }()

	serials, err := ca.ParseRevokedSerials(f)
	if err != nil {
		return nil, fmt.Errorf("parse revoked file %s: %w", path, err)
	}

	return serials, nil
}

// handleConn reads the peer's Hello off the first stream it opens and
// dispatches to Registry.Register (publish) or Registry.Bridge
// (subscribe) for the life of the connection.
//
// Deliberately absent: any call to conn.CloseWithError. Every path here
// either ends because the peer (or quic-go's own MaxIdleTimeout) already
// closed the connection - so conn.Context() is already Done and an active
// close would be a no-op - or ends right after writing a rejection ack,
// where an active close could race the peer's read of that very ack (see
// Registry.Bridge's doc comment). Letting quic-go's idle timeout reap
// anything that goes quiet, instead of racing to close it ourselves, is
// what makes every path here safe by construction rather than by a tuned
// grace period.
func handleConn(ctx context.Context, logger *slog.Logger, registry *Registry, conn *quic.Conn) {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}

	hello, err := proto.ReadHello(stream)
	if err != nil {
		logger.WarnContext(ctx, "read hello", "peer", conn.RemoteAddr(), "err", err)
		return
	}

	switch hello.Role {
	case proto.RolePublish:
		unregister, err := registry.Register(stream, hello.Token, hello.Mode, conn)
		if err != nil {
			logger.WarnContext(ctx, "register publisher", "peer", conn.RemoteAddr(), "err", err)
			return
		}
		defer unregister()

		logger.InfoContext(ctx, "publisher registered", "peer", conn.RemoteAddr(), "mode", hello.Mode)
		<-conn.Context().Done()

	case proto.RoleSubscribe:
		logger.InfoContext(ctx, "subscriber bridging", "peer", conn.RemoteAddr(), "mode", hello.Mode)
		if err := registry.Bridge(ctx, stream, hello.Token, hello.Mode, conn); err != nil {
			logger.WarnContext(ctx, "bridge subscriber", "peer", conn.RemoteAddr(), "err", err)
		}
	}
}
