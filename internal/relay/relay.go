package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/proto"
)

// helloTimeout bounds how long relay waits for a freshly accepted TCP
// connection to send its ConnKind and then a Hello (control) or Attach (data).
// A peer that connects and never sends anything would otherwise sit open forever.
const helloTimeout = 10 * time.Second

// heartbeatSilenceTimeout is how long relay waits without receiving
// anything on a control connection before treating the peer as dead.
// share/listen send a ControlPing well inside this window, so exceeding
// it means the peer is gone or hung - see runHeartbeatLoop.
const heartbeatSilenceTimeout = 30 * time.Second

// Config is the input to Run.
type Config struct {
	// Listen is the address relay's TCP listener binds to. Its UDP-mode
	// QUIC listener binds the same host:port - TCP and UDP have separate
	// port namespaces, so this never conflicts.
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

	// Logger, if non-nil, receives relay's per-connection attach/detach
	// records instead of the default stderr handler. Mainly for tests and
	// benchmarks that run a relay in-process, where the default's output
	// would interleave with - and bury - their own.
	Logger *slog.Logger
}

// Run listens for TCP and QUIC connections on Config.Listen and brokers
// them between share (publisher) and listen (subscriber) peers until ctx
// is canceled. TCP carries every control connection and TCP-mode's data
// connections; QUIC carries only UDP-mode's data-plane connections, one
// per attached publisher/subscriber, each already implied to exist by a
// prior TCP control connection's successful Register/Subscribe.
func Run(ctx context.Context, cfg Config) error {
	revoked, err := loadRevokedSerials(cfg.RevokedFile)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}

	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, true, revoked)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}

	listener, err := tls.Listen("tcp", cfg.Listen.String(), tlsConf)
	if err != nil {
		return fmt.Errorf("relay: listen on %s: %w", cfg.Listen, err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	registry := NewRegistry(logger)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("relay: accept: %w", err)
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			// tls.Listen's Listener always hands back *tls.Conn from
			// Accept; this is unreachable in practice, but fail closed
			// rather than panic on a type assertion further down.
			_ = conn.Close()
			continue
		}

		go handleConn(ctx, logger, registry, tlsConn)
	}
}

// loadRevokedSerials reads path via ca.ParseRevokedSerials. An empty path
// is not an error - it just means Run skips revocation checking entirely,
// same as an operator who never ran ca crl.
func loadRevokedSerials(path string) (map[string]struct{}, error) {
	if path == "" {
		return map[string]struct{}{}, nil
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

// handleConn reads the ConnKind a peer sends immediately after connecting
// - before anything else, including the TLS handshake proper, which
// Read/Write trigger lazily - and dispatches to handleControlConn or
// handleDataConn. It owns closing conn only for the cases where neither
// of those takes over that responsibility (see their doc comments).
func handleConn(ctx context.Context, logger *slog.Logger, registry *Registry, conn *tls.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(helloTimeout))

	kind, err := proto.ReadConnKind(conn)
	if err != nil {
		logger.WarnContext(ctx, "read conn kind", "peer", conn.RemoteAddr(), "err", err)
		_ = conn.Close()
		return
	}

	switch kind {
	case proto.ConnControl:
		handleControlConn(ctx, logger, registry, conn)
	case proto.ConnData:
		handleDataConn(ctx, logger, registry, conn)
	default:
		_ = conn.Close()
	}
}

// handleControlConn reads a Hello and dispatches to Registry.Register
// (publish) or Registry.Subscribe (subscribe), then runs the heartbeat
// loop for the life of the session. It always closes conn before
// returning. The registry logs the session lifecycle itself - who
// registered, who attached, and when each of them went away - so what's
// left here is only the connections that never got that far.
func handleControlConn(ctx context.Context, logger *slog.Logger, registry *Registry, conn *tls.Conn) {
	defer func() { _ = conn.Close() }()

	hello, err := proto.ReadHello(conn)
	if err != nil {
		logger.WarnContext(ctx, "read hello", "peer", conn.RemoteAddr(), "err", err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // runHeartbeatLoop manages its own deadlines from here

	switch hello.Role {
	case proto.RolePublish:
		unregister, err := registry.Register(conn, hello.Token, hello.Mode, hello.Ports)
		if err != nil {
			logger.WarnContext(ctx, "register publisher", "peer", conn.RemoteAddr(), "err", err)
			return
		}
		defer unregister()

		runHeartbeatLoop(ctx, conn)

	case proto.RoleSubscribe:
		_, release, err := registry.Subscribe(conn, hello.Token, hello.Mode, hello.Ports)
		if err != nil {
			logger.WarnContext(ctx, "subscribe", "peer", conn.RemoteAddr(), "err", err)
			return
		}
		defer release()

		runHeartbeatLoop(ctx, conn)
	}
}

// runHeartbeatLoop reads ControlType frames off conn, replying to every
// ControlPing with a ControlPong, until conn errors, goes silent for
// longer than heartbeatSilenceTimeout, or ctx is canceled. share/listen
// are the ones that periodically send ControlPing (see their own
// heartbeatInterval) - relay only ever replies - so a silence timeout
// here is what lets relay notice a publisher/subscriber that's gone or
// hung, symmetric to how share/listen notice a dead relay by timing out
// waiting for a ControlPong.
func runHeartbeatLoop(ctx context.Context, conn *tls.Conn) {
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(heartbeatSilenceTimeout))

		typ, _, err := proto.ReadControlFrame(conn)
		if err != nil {
			return
		}

		if typ == proto.ControlPing {
			if err := proto.WriteControlFrame(conn, proto.ControlPong, nil); err != nil {
				return
			}
		}
	}
}

// handleDataConn reads the Attach a peer sends on a fresh TCP-mode data
// connection and pairs it with its counterpart via the registry. It
// closes conn itself only on a failure path - on success, ownership of
// conn has passed into Registry.AttachSubscriberData/AttachPublisherData
// (see their doc comments for why).
func handleDataConn(ctx context.Context, logger *slog.Logger, registry *Registry, conn *tls.Conn) {
	attach, err := proto.ReadAttach(conn)
	if err != nil {
		logger.WarnContext(ctx, "read attach", "peer", conn.RemoteAddr(), "err", err)
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch attach.Kind {
	case proto.AttachSubscriber:
		if err := registry.AttachSubscriberData(conn, attach.Token, attach.Port); err != nil {
			logger.WarnContext(ctx, "attach subscriber data", "peer", conn.RemoteAddr(), "err", err)
			_ = conn.Close()
		}

	case proto.AttachPublisher:
		if err := registry.AttachPublisherData(attach.Token, attach.RequestID, conn); err != nil {
			logger.WarnContext(ctx, "attach publisher data", "peer", conn.RemoteAddr(), "err", err)
			_ = conn.Close()
		}

	default:
		_ = conn.Close()
	}
}
