// Package share is the publisher side of a tunnel: it dials relay, registers
// under proto.RolePublish, and for every connection relay asks it for, dials
// the local service and forwards bytes. relay never terminates the forwarded
// service - it only pairs this connection with however many listen
// subscribers present the matching token, and what it splices between them is
// ciphertext only the two peers can read.
package share

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/peer"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
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

	// Addr is the local service being forwarded - share dials it fresh for
	// every connection relay asks it for. A range of more than one port
	// forwards each of them, and every subscriber has to bind a range of the
	// same size: what crosses the wire is an index into this range, not a
	// port number (see proto.PortIndex).
	Addr hostport.Range

	// Token scopes which listen subscribers may reach this session.
	Token proto.Token
}

// Run dials relay, registers Config.Token as a publisher, and forwards
// traffic to Config.Addr until ctx is canceled or an unrecoverable error
// occurs.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Addr.Len() < 1 {
		return fmt.Errorf("share: no local address to forward")
	}

	tlsConf, err := mtls.LoadConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, false, nil)
	if err != nil {
		return fmt.Errorf("share: %w", err)
	}

	session := peer.NewSession(cfg.Server, tlsConf, cfg.Token, proto.RolePublish)

	control, err := session.DialControl(ctx)
	if err != nil {
		return fmt.Errorf("share: %w", err)
	}
	defer func() { _ = control.Close() }()

	ports := uint16(cfg.Addr.Len()) //nolint:gosec // hostport.ParseRange bounds a range at MaxPorts

	if err := session.Handshake(control, cfg.Mode, ports); err != nil {
		return fmt.Errorf("share: %w", err)
	}

	switch cfg.Mode {
	case proto.ModeTCP:
		return runTCP(ctx, session, control, cfg.Addr)
	default:
		return fmt.Errorf("share: unsupported mode %v", cfg.Mode)
	}
}

// runTCP runs share's TCP-mode data plane: for every ControlRequestData
// relay sends on control, it opens a tunnel, dials the local service, and
// splices the two together. It runs until ctx is canceled or the control
// connection dies.
func runTCP(ctx context.Context, session peer.Session, control *tls.Conn, addr hostport.Range) error {
	// The control loop below is the only thing this function blocks on, and
	// its read has no way to notice ctx being canceled on its own - it only
	// unblocks whenever the next ControlPong happens to arrive, up to a
	// heartbeat interval later. Closing control out from under it the moment
	// ctx is done is what makes Ctrl+C take effect immediately instead of
	// that much late.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = control.Close()
		case <-stop:
		}
	}()

	return peer.RunControlLoop(ctx, control, func(typ proto.ControlType, payload []byte) error {
		if typ != proto.ControlRequestData {
			return nil
		}

		// A frame a misbehaving relay malformed is dropped rather than
		// treated as the end of the session. What is well-formed is
		// dispatched in a goroutine of its own, so a slow local dial doesn't
		// stall the read loop - and with it, every other in-flight request.
		if reqID, port, err := proto.ReadRequestData(payload); err == nil {
			go fulfill(ctx, session, addr, reqID, port)
		}

		return nil
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

	tunnel, err := session.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachPublisher, RequestID: reqID})
	if err != nil {
		return
	}

	var dialer net.Dialer
	localConn, err := dialer.DialContext(ctx, "tcp", local.String())
	if err != nil {
		_ = tunnel.Close()
		return
	}

	streamio.Splice(tunnel, localConn)
}
