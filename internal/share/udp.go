package share

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
)

const (
	// udpIdleTimeout and udpSweepInterval bound how long a NAT entry's
	// local socket lingers with no traffic before it's closed, so a
	// long-lived share doesn't accumulate one socket per remote client
	// forever.
	udpIdleTimeout   = 2 * time.Minute
	udpSweepInterval = 30 * time.Second

	// udpReadBufferSize is the max size of a single reply read from a
	// NAT entry's local socket before it's forwarded as a datagram.
	udpReadBufferSize = 64 * 1024
)

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

// runUDP is the UDP-mode counterpart to runTCP: it reads relay-framed
// datagrams off conn, routes each to a per-(subscriber, flow) local UDP
// socket dialed to addr, and forwards that socket's replies back the same
// way.
func runUDP(ctx context.Context, conn *quic.Conn, addr hostport.HostPort) error {
	table := &natTable{entries: make(map[natKey]*natEntry)}
	defer table.closeAll()

	go table.sweep(ctx)

	for {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return fmt.Errorf("receive datagram: %w", err)
		}

		sub, flow, payload, err := proto.DecodePublisherFrame(data)
		if err != nil {
			continue // malformed frame from a misbehaving relay; drop it
		}

		entry, err := table.get(ctx, conn, addr, sub, flow)
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
	conn *quic.Conn,
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

	go t.pump(conn, local, key)

	return entry, nil
}

// pump reads replies from a NAT entry's local socket and forwards them
// back through conn, tagged with the header that routes them to the right
// subscriber's right local client. It runs until the local socket errors
// or closes, then evicts its own entry.
func (t *natTable) pump(conn *quic.Conn, local net.Conn, key natKey) {
	buf := make([]byte, udpReadBufferSize)
	for {
		n, err := local.Read(buf)
		if err != nil {
			t.evict(key)
			return
		}

		if err := conn.SendDatagram(proto.EncodePublisherFrame(key.sub, key.flow, buf[:n])); err != nil {
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
