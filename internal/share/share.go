// Package share is the publisher side of a tunnel: it dials relay, registers
// under proto.RolePublish, and for every connection relay asks it for, dials
// the local service and forwards bytes. relay never terminates the forwarded
// service - it only pairs this connection with however many listen
// subscribers present the matching subscriber token, and what it splices
// between them is ciphertext only the two peers can read.
package share

import (
	"context"
	"fmt"
	"net"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/peer"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// localDialTimeout bounds attempts to reach a shared service.
const localDialTimeout = 10 * time.Second

// Config is the input to Run.
type Config struct {
	// Server is relay's listen address.
	Server hostport.HostPort

	// CertFile, KeyFile, and CAFile identify this share to relay and
	// verify relay's own certificate, per internal/mtls.
	CertFile, KeyFile, CAFile string

	// Mode is which kind of local service Addr names.
	Mode proto.Mode

	// Addr is the local service being forwarded - share dials it fresh for
	// every connection relay asks it for. A range of more than one port
	// forwards each of them, and every subscriber has to bind a range of the
	// same size: what crosses the wire is an index into this range, not a
	// port number (see proto.PortIndex).
	Addr hostport.Range

	// SessionKey is this session's root secret. Everything else is derived
	// from it: the identifier relay routes by, the signing key that proves
	// to relay the session is ours, and the subscriber token to hand out
	// (see proto.Credentials).
	SessionKey proto.SessionKey

	// OnDisconnect and OnReconnect, if non-nil, report the session losing
	// relay and getting it back. Run keeps redialing rather than returning
	// on a lost connection (see [peer.Session.Serve]), so without these a
	// share whose relay is unreachable is indistinguishable from one that's
	// simply idle. OnDisconnect is given the error that ended the session
	// and how long until the next attempt.
	OnDisconnect func(err error, retryIn time.Duration)
	OnReconnect  func()
}

// Run registers Config.SessionKey's session as a publisher and forwards
// traffic to Config.Addr until ctx is canceled or an unrecoverable error
// occurs. A relay that goes away is redialed rather than reported: see
// [peer.Session.Serve] for what counts as unrecoverable, and
// Config.OnDisconnect for how to hear about the rest.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Addr.Len() < 1 {
		return fmt.Errorf("share: no local address to forward")
	}

	creds, err := cfg.SessionKey.Credentials()
	if err != nil {
		return fmt.Errorf("share: %w", err)
	}

	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, false, nil)
	if err != nil {
		return fmt.Errorf("share: %w", err)
	}

	session := peer.NewSession(cfg.Server, tlsConf, creds, proto.RolePublish)

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, session, cfg)
	default:
		return fmt.Errorf("share: unsupported mode %v", cfg.Mode)
	}
}

// runTCP runs share's TCP-mode data plane: for every ControlRequestData
// relay sends, it opens a tunnel, dials the local service, and splices the
// two together. Serve holds the control connection up across reconnects, so
// this runs until ctx is canceled or the session turns out to be one no
// redial can restore.
func runTCP(ctx context.Context, session peer.Session, cfg Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	slots := make(chan struct{}, peer.MaxTunnels)
	return session.Serve(ctx, peer.ServeConfig{
		Mode:  cfg.Mode,
		Ports: uint16(cfg.Addr.Len()), //nolint:gosec // hostport.ParseRange bounds a range at MaxPorts
		Handle: func(typ proto.ControlType, payload []byte) error {
			if typ != proto.ControlRequestData {
				return nil
			}

			// A frame a misbehaving relay malformed is dropped rather than
			// treated as the end of the session. What is well-formed is
			// dispatched in a goroutine of its own, so a slow local dial
			// doesn't stall the read loop - and with it, every other
			// in-flight request.
			if reqID, port, err := proto.ReadRequestData(payload); err == nil {
				select {
				case slots <- struct{}{}:
					go func() {
						defer func() { <-slots }()
						fulfill(ctx, session, cfg.Addr, reqID, port)
					}()
				default:
					// relay will expire requests beyond our capacity.
				}
			}

			return nil
		},
		OnReconnect:  cfg.OnReconnect,
		OnDisconnect: cfg.OnDisconnect,
	})
}

// fulfill answers one ControlRequestData: it opens the tunnel relay asked
// for under reqID, dials the local service at index port of addr, and
// splices the two. Every failure before the splice drops whatever it had
// opened - relay times the pending request out on its own.
func fulfill(
	ctx context.Context,
	session peer.Session,
	addr hostport.Range,
	reqID uint64,
	port proto.PortIndex,
) {
	// relay checks the index against the port count this share registered,
	// but relay is the one that supplied it - so it's checked again here
	// against the range this process actually holds, which is the only
	// authority on what "index 3" means locally.
	local, ok := addr.At(int(port))
	if !ok {
		return
	}

	tunnel, err := session.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachPublisher, RequestID: reqID, Port: port})
	if err != nil {
		return
	}

	defer func() { _ = tunnel.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = tunnel.Close() })
	defer stop()

	dialer := net.Dialer{Timeout: localDialTimeout}
	localConn, err := dialer.DialContext(ctx, "tcp", local.String())
	if err != nil {
		_ = tunnel.Close()
		return
	}

	streamio.Splice(tunnel, localConn)
}
