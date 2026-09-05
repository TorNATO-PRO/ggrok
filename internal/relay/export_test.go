package relay

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"

	"tornato.dev/ggrok/v2/internal/mtls"
)

// TestServerConfig is the per-relay policy Run derives from its Config,
// exposed so transport integration tests can exercise both sides of each
// gate without standing up a full Run.
type TestServerConfig struct {
	// Admin mirrors Config.Admin.
	Admin bool

	// Revoked and RevokedFile mirror what Run holds so an admin reload has
	// something to read and something to swap. Leaving RevokedFile empty
	// exercises the arm where a relay was started without one.
	Revoked     *mtls.RevocationSet
	RevokedFile string
}

// HandleConnFunc returns Run's connection dispatcher for transport
// integration tests.
func HandleConnFunc(
	logger *slog.Logger,
	registry *Registry,
	cfg TestServerConfig,
) func(context.Context, net.Conn, *tls.Config) {
	var connections connectionSet
	if cfg.Revoked == nil {
		cfg.Revoked = mtls.NewRevocationSet(nil)
	}
	srv := &server{
		logger:      logger,
		registry:    registry,
		admin:       cfg.Admin,
		revoked:     cfg.Revoked,
		revokedFile: cfg.RevokedFile,
		connections: &connections,
	}

	return func(ctx context.Context, conn net.Conn, config *tls.Config) {
		tracked, ok := connections.track(conn)
		if !ok {
			_ = conn.Close()
			return
		}
		srv.handleConn(ctx, tls.Server(tracked, config))
	}
}
