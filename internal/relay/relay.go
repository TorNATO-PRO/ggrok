package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
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
	// Listen is the address relay's TCP listener binds to, carrying both
	// control connections and per-stream data connections.
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

	// Admin enables relay's admin plane: without it, a ConnAdmin connection
	// is refused no matter what certificate it presents. It defaults off so
	// that an operator who wants no control plane has no admin surface at
	// all, rather than one whose safety rests entirely on nobody holding a
	// certificate with the role. The role check is the second gate, not the
	// only one.
	Admin bool

	// Logger, if non-nil, receives relay's per-connection attach/detach
	// records instead of the default stderr handler. Mainly for tests and
	// benchmarks that run a relay in-process, where the default's output
	// would interleave with - and bury - their own.
	Logger *slog.Logger
}

// Run listens on Config.Listen and brokers connections between share
// (publisher) and listen (subscriber) peers until ctx is canceled. Every
// connection announces itself with a proto.ConnKind: one control connection
// per peer for the life of its session, and one short-lived data connection
// per forwarded stream.
func Run(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	serials, err := loadRevokedSerials(cfg.RevokedFile)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	revoked := mtls.NewRevocationSet(serials)

	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, true, revoked)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", cfg.Listen.String())
	if err != nil {
		return fmt.Errorf("relay: listen on %s: %w", cfg.Listen, err)
	}
	defer func() { _ = listener.Close() }()
	var connections connectionSet
	defer connections.closeAll()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	srv := &server{
		logger:      logger,
		registry:    NewRegistry(logger),
		admin:       cfg.Admin,
		revoked:     revoked,
		revokedFile: cfg.RevokedFile,
		connections: &connections,
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("relay: accept: %w", err)
		}

		tracked, ok := connections.track(conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		tlsConn := tls.Server(tracked, tlsConf)

		go srv.handleConn(ctx, tlsConn)
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

// server is the per-relay state a connection handler needs beyond the
// registry: what to log to, and which planes are enabled. It exists so the
// dispatcher's signature stays readable as relay grows policy that is neither
// session state nor connection state.
type server struct {
	connections *connectionSet
	reloadMu    sync.Mutex
	logger      *slog.Logger
	registry    *Registry

	// admin mirrors Config.Admin.
	admin bool

	// revoked is the live revocation set the TLS config consults on every
	// handshake, and revokedFile is where reloading it reads from. Held
	// here rather than captured at startup so `admin reload-crl` has
	// something to swap.
	revoked     *mtls.RevocationSet
	revokedFile string
}

// handleConn reads the ConnKind a peer sends immediately after connecting -
// which is also what drives the TLS handshake, since Read/Write trigger it
// lazily - and dispatches to the handler for that kind. It owns closing conn
// only in the cases where none of those takes over that responsibility (see
// their doc comments).
func (s *server) handleConn(ctx context.Context, conn *tls.Conn) {
	_ = conn.SetDeadline(time.Now().Add(helloTimeout))

	kind, err := proto.ReadConnKind(conn)
	if err != nil {
		s.logger.WarnContext(ctx, "read conn kind", "peer", conn.RemoteAddr(), "err", err)
		_ = conn.Close()
		return
	}

	if conn.ConnectionState().NegotiatedProtocol != proto.ALPN {
		_ = conn.Close()
		return
	}

	cert, err := peerLeafCert(conn)
	if err != nil || !s.connections.authenticate(conn.NetConn(), cert.SerialNumber.Text(ca.SerialTextBase), s.revoked) {
		_ = conn.Close()
		return
	}

	switch kind {
	case proto.ConnControl:
		handleControlConn(ctx, s.logger, s.registry, conn)
	case proto.ConnData:
		handleDataConn(ctx, s.logger, s.registry, conn)
	case proto.ConnAdmin:
		if !s.admin {
			// Closed without a refusal frame, deliberately. The gate is
			// off, so this relay has no admin plane to be refused by,
			// and saying so would tell an unauthenticated scan which
			// relays are worth returning to with a better certificate.
			s.logger.WarnContext(ctx, "admin connection refused: admin plane is disabled",
				"peer", conn.RemoteAddr())
			_ = conn.Close()

			return
		}
		s.handleAdminConn(ctx, conn)
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

	switch hello.Role {
	case proto.RolePublish:
		// The helloTimeout deadline is still live here, and has to be:
		// Register challenges a publisher to sign for its session, and a
		// claimant that goes quiet mid-exchange would otherwise hold the
		// connection open indefinitely.
		unregister, err := registry.Register(conn, hello)
		if err != nil {
			logger.WarnContext(ctx, "register publisher", "peer", conn.RemoteAddr(), "err", err)
			return
		}
		defer unregister()

		_ = conn.SetReadDeadline(time.Time{}) // runHeartbeatLoop manages its own deadlines from here
		runHeartbeatLoop(ctx, conn)

	case proto.RoleSubscribe:
		_, release, err := registry.Subscribe(conn, hello)
		if err != nil {
			logger.WarnContext(ctx, "subscribe", "peer", conn.RemoteAddr(), "err", err)
			return
		}
		defer release()

		_ = conn.SetReadDeadline(time.Time{})
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
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	for ctx.Err() == nil {
		_ = conn.SetDeadline(time.Now().Add(heartbeatSilenceTimeout))

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

// handleDataConn reads the Attach a peer sends on a fresh data connection and
// pairs it with its counterpart via the registry. It
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
		if err := registry.AttachSubscriberData(conn, attach.SessionID, attach.Port); err != nil {
			logger.WarnContext(ctx, "attach subscriber data", "peer", conn.RemoteAddr(), "err", err)
			_ = conn.Close()
		}

	case proto.AttachPublisher:
		if err := registry.AttachPublisherData(attach.SessionID, attach.RequestID, conn); err != nil {
			logger.WarnContext(ctx, "attach publisher data", "peer", conn.RemoteAddr(), "err", err)
			_ = conn.Close()
		}

	default:
		_ = conn.Close()
	}
}
