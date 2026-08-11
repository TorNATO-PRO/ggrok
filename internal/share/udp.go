package share

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/udpcrypto"
)

const (
	// udpIdleTimeout and udpSweepInterval bound how long a NAT entry's
	// local socket lingers with no traffic before it's closed, so a
	// long-lived share doesn't accumulate one socket per remote client
	// forever.
	udpIdleTimeout   = 2 * time.Minute
	udpSweepInterval = 30 * time.Second

	// udpReadBufferSize is the max size of a single reply read from a
	// NAT entry's local socket, or a single datagram read off udpSession,
	// before it's forwarded on.
	udpReadBufferSize = 64 * 1024
)

// setupUDPSession reads the ControlUDPSession frame relay sends
// immediately after a successful UDP-mode Handshake, derives this hop's
// AEAD key pair off control's own connection state (RFC 5705 - no key
// material crosses the wire; both ends of the same TLS connection derive
// identical output for identical inputs), dials relay's UDP data socket,
// and returns a ready-to-use udpcrypto.Session.
func setupUDPSession(
	ctx context.Context,
	control *tls.Conn,
	server hostport.HostPort,
	token proto.Token,
) (*udpcrypto.Session, error) {
	typ, payload, err := proto.ReadControlFrame(control)
	if err != nil {
		return nil, fmt.Errorf("read udp session: %w", err)
	}
	if typ != proto.ControlUDPSession {
		return nil, fmt.Errorf("expected ControlUDPSession, got frame type %d", typ)
	}

	routing, err := proto.ReadUDPSession(payload)
	if err != nil {
		return nil, err
	}

	state := control.ConnectionState()
	sendKey, err := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionUplink)
	if err != nil {
		return nil, err
	}
	recvKey, err := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionDownlink)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	udpConn, err := dialer.DialContext(ctx, "udp", server.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s udp: %w", server, err)
	}

	session, err := udpcrypto.NewSession(udpConn, routing, sendKey, recvKey)
	if err != nil {
		return nil, err
	}

	// relay only learns this hop's source address from a packet it
	// actually receives - an empty punch datagram right now guarantees
	// that happens before any real traffic needs to flow, rather than
	// leaving it to chance which side happens to send first.
	if err := session.Send(nil); err != nil {
		return nil, fmt.Errorf("punch udp session: %w", err)
	}

	return session, nil
}

// natKey identifies one virtual remote client: a specific local client of
// a specific subscriber, disambiguated since many subscribers' traffic
// shares this one publisher connection.
type natKey struct {
	sub  proto.SubscriberID
	flow proto.FlowID
}

// natEntry is one NAT table slot: a local UDP socket dialed to the shared
// service, dedicated to a single (subscriber, flow) pair so the service
// sees it as a distinct remote peer.
type natEntry struct {
	conn       net.Conn
	lastActive time.Time
}

// natTable is share's UDP-mode NAT: it demultiplexes datagrams arriving
// from potentially many subscribers' many local clients, each getting its
// own local socket dialed to the shared service.
type natTable struct {
	mu      sync.Mutex
	entries map[natKey]*natEntry
}

// runUDP is share's UDP-mode data plane: it reads relay-framed datagrams
// off udpSession, routes each to a per-(subscriber, flow) local UDP
// socket dialed to addr, and forwards that socket's replies back the same
// way. It runs until ctx is canceled, udpSession errors, or the control
// connection's heartbeat loop decides relay is dead.
func runUDP(ctx context.Context, control *tls.Conn, udpSession *udpcrypto.Session, addr hostport.HostPort) error {
	table := &natTable{entries: make(map[natKey]*natEntry)}
	defer table.closeAll()

	go table.sweep(ctx)

	heartbeatErr := make(chan error, 1)
	go func() { heartbeatErr <- runControlLoop(ctx, control, func(uint64) {}) }()

	buf := make([]byte, udpReadBufferSize)
	for {
		data, err := udpSession.Recv(buf)
		if err != nil {
			select {
			case hErr := <-heartbeatErr:
				return fmt.Errorf("control connection: %w", hErr)
			default:
				return fmt.Errorf("receive datagram: %w", err)
			}
		}

		sub, flow, payload, err := proto.DecodePublisherFrame(data)
		if err != nil {
			continue // malformed frame from a misbehaving relay; drop it
		}

		entry, err := table.get(ctx, udpSession, addr, sub, flow)
		if err != nil {
			continue // local dial failed; drop this datagram, the next one retries
		}

		_, _ = entry.conn.Write(payload) // best-effort; a dead local socket just misses this one datagram
	}
}

// get returns the NAT entry for key, dialing a fresh local socket and
// starting its reply-pump goroutine if this is the first datagram seen for
// that (subscriber, flow) pair.
func (t *natTable) get(
	ctx context.Context,
	udpSession *udpcrypto.Session,
	addr hostport.HostPort,
	sub proto.SubscriberID,
	flow proto.FlowID,
) (*natEntry, error) {
	key := natKey{sub: sub, flow: flow}

	t.mu.Lock()
	entry, ok := t.entries[key]
	if ok {
		entry.lastActive = time.Now()
	}
	t.mu.Unlock()

	if ok {
		return entry, nil
	}

	var dialer net.Dialer
	local, err := dialer.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s for new flow: %w", addr, err)
	}

	entry = &natEntry{conn: local, lastActive: time.Now()}

	t.mu.Lock()
	t.entries[key] = entry
	t.mu.Unlock()

	go t.pump(udpSession, local, key)

	return entry, nil
}

// pump reads replies from a NAT entry's local socket and forwards them
// back through udpSession, tagged with the header that routes them to the
// right subscriber's right local client. It runs until the local socket
// errors or closes, then evicts its own entry.
func (t *natTable) pump(udpSession *udpcrypto.Session, local net.Conn, key natKey) {
	buf := make([]byte, udpReadBufferSize)
	for {
		n, err := local.Read(buf)
		if err != nil {
			t.evict(key)
			return
		}

		if err := udpSession.Send(proto.EncodePublisherFrame(key.sub, key.flow, buf[:n])); err != nil {
			t.evict(key)
			return
		}

		t.touch(key)
	}
}

// touch refreshes a NAT entry's idle clock - called on replies too, so a
// service that pushes data without being written to first still counts as
// active traffic.
func (t *natTable) touch(key natKey) {
	t.mu.Lock()
	if entry, ok := t.entries[key]; ok {
		entry.lastActive = time.Now()
	}
	t.mu.Unlock()
}

// evict removes and closes a single NAT entry.
func (t *natTable) evict(key natKey) {
	t.mu.Lock()
	entry, ok := t.entries[key]
	if ok {
		delete(t.entries, key)
	}
	t.mu.Unlock()

	if ok {
		_ = entry.conn.Close()
	}
}

// sweep periodically closes and removes NAT entries idle for longer than
// udpIdleTimeout, until ctx is canceled.
func (t *natTable) sweep(ctx context.Context) {
	ticker := time.NewTicker(udpSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sweepOnce()
		}
	}
}

// sweepOnce evicts every entry idle for longer than udpIdleTimeout.
func (t *natTable) sweepOnce() {
	cutoff := time.Now().Add(-udpIdleTimeout)

	var stale []net.Conn
	t.mu.Lock()
	for key, entry := range t.entries {
		if entry.lastActive.Before(cutoff) {
			stale = append(stale, entry.conn)
			delete(t.entries, key)
		}
	}
	t.mu.Unlock()

	for _, conn := range stale {
		_ = conn.Close()
	}
}

// closeAll closes every remaining NAT entry's local socket, used when
// runUDP itself returns.
func (t *natTable) closeAll() {
	t.mu.Lock()
	entries := t.entries
	t.entries = make(map[natKey]*natEntry)
	t.mu.Unlock()

	for _, entry := range entries {
		_ = entry.conn.Close()
	}
}
