// Package peer holds what share (publisher) and listen (subscriber) do
// identically on their way to a tunnel: dialing relay over mTLS, keeping a
// control connection alive on it, and opening an encrypted data connection
// per forwarded stream. The two differ only in what they do with a tunnel
// once they hold one - share dials a local service, listen accepts from one
// - and that difference is all their own packages are left carrying.
package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
)

// TCP keepalive settings for every connection a peer opens to relay. This
// catches a severed network path; the application-level heartbeat in
// [RunControlLoop] catches a peer that's still connected but hung.
const (
	tcpKeepAliveIdle       = 15 * time.Second
	tcpKeepAliveInterval   = 15 * time.Second
	tcpKeepAliveProbeCount = 2
)

// dialTimeout bounds one attempt to reach relay. A relay that's merely gone
// refuses connections immediately, but one whose host has dropped off the
// network blackholes the SYN instead, and the OS would spend minutes on
// that. [Session.Serve] is happier being told quickly so it can back off
// and try again, and a subscriber's [Session.OpenTunnel] would otherwise
// hold a local client open for those same minutes rather than closing it
// and letting the client decide what to do.
const dialTimeout = 10 * time.Second

// MaxTunnels bounds concurrent active and establishing tunnels per peer process.
const MaxTunnels = 256

// ErrProtocolMismatch means relay and this peer need compatible versions.
var ErrProtocolMismatch = errors.New("relay protocol mismatch; upgrade relay, share, and listen together")

// Session is everything a peer needs to open connections to relay for one
// session: where relay is, how to authenticate to it, and the credentials
// whose derived keys seal the tunnels it opens.
//
// No secret in those credentials reaches the wire. What identifies the
// session to relay is their SessionID, which is enough to route by and not
// enough to decrypt with; a publisher additionally signs for it, which proves
// the session is its own without handing over what did the signing.
type Session struct {
	relay hostport.HostPort
	tls   *tls.Config
	creds proto.Credentials
	role  proto.Role
	id    proto.SessionID
}

// NewSession pairs relay's address and TLS config with the credentials and
// role this peer holds, lifting out the session's routing identifier up front
// - every connection the session opens names the same one.
func NewSession(
	relay hostport.HostPort,
	tlsConf *tls.Config,
	creds proto.Credentials,
	role proto.Role,
) Session {
	return Session{
		relay: relay,
		tls:   tlsConf,
		creds: creds,
		role:  role,
		id:    creds.SessionID(),
	}
}

// OpenTunnel dials relay a fresh data connection, attaches it to this
// session, and returns the encrypted stream to splice a local connection
// to. attach's SessionID is filled in from the session, so callers supply
// only what distinguishes this connection from the others: its Kind, and
// the Port or RequestID that goes with it.
//
// Everything past the Attach is sealed end-to-end, so what relay splices is
// ciphertext: it pairs this connection with its counterpart by SessionID
// without holding the token those keys come from.
//
// A non-nil error leaves nothing open - the data connection is closed on
// the way out. On success the returned tunnel owns it, and closing the
// tunnel is what closes it.
func (s Session) OpenTunnel(ctx context.Context, attach proto.Attach) (*proto.EncryptedConn, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	tunnel, err := s.attach(conn, attach)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	return tunnel, nil
}

// attach writes attach on conn, waits for relay's verdict where there is
// one, and wraps conn for this session's role. Split out of OpenTunnel so
// every failure between the dial and a usable tunnel closes conn on one
// path rather than each on its own.
func (s Session) attach(conn *tls.Conn, attach proto.Attach) (*proto.EncryptedConn, error) {
	attach.SessionID = s.id
	if err := proto.WriteDataAttach(conn, attach); err != nil {
		return nil, fmt.Errorf("send tunnel request: %w", err)
	}

	// Only a subscriber's attach is acked: it asks relay to find it a
	// publisher, and the ack is how relay says there isn't one (or that the
	// port index named nothing). A publisher's attach fulfills a request
	// relay already made, so relay has nothing left to accept or reject and
	// sends no ack to wait for - see Registry.AttachPublisherData.
	if attach.Kind == proto.AttachSubscriber {
		status, err := proto.ReadAck(conn)
		if err != nil {
			return nil, fmt.Errorf("read relay tunnel response: %w", err)
		}

		if err := status.Err(); err != nil {
			return nil, fmt.Errorf("relay refused tunnel: %w", err)
		}
	}

	return proto.NewAuthenticatedConn(conn, s.creds, s.role, attach.Port)
}

// dial dials relay over TCP+mTLS. The caller writes the discriminator
// alongside its control or data handshake.
func (s Session) dial(ctx context.Context) (*tls.Conn, error) {
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: s.tls}

	// The deadline covers reaching relay and nothing after it: per
	// [tls.Dialer.DialContext], a context that expires once the connection
	// is up no longer affects it, so this can't cut a live tunnel short.
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", s.relay.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", s.relay, err)
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		// tls.Dialer.DialContext always returns a *tls.Conn; unreachable
		// in practice, but fail closed rather than panic on assertion.
		_ = conn.Close()
		return nil, fmt.Errorf("dial %s: unexpected connection type %T", s.relay, conn)
	}

	if tlsConn.ConnectionState().NegotiatedProtocol != proto.ALPN {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("%w (expected %s)", ErrProtocolMismatch, proto.ALPN)
	}

	_ = tlsConn.SetDeadline(time.Now().Add(dialTimeout))
	setTCPKeepAlive(tlsConn)

	return tlsConn, nil
}

// setTCPKeepAlive best-effort enables TCP keepalive on conn's underlying
// socket, per tcpKeepAliveIdle/Interval/ProbeCount - a no-op if conn isn't
// backed by a [net.TCPConn]. A data connection is spliced raw bytes with no
// application-level heartbeat of its own, so without this, a path a
// NAT/firewall silently drops while the tunnel is idle goes unnoticed until
// the next write.
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
