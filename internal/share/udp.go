package share

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/dgram"
	"tornato.dev/ggrok/v2/internal/proto"
)

const (
	// udpIdleTimeout and udpSweepInterval bound how long a NAT entry's
	// local socket lingers with no traffic before it's closed, so a
	// long-lived share doesn't accumulate one socket per remote client
	// forever.
	udpIdleTimeout   = 2 * time.Minute
	udpSweepInterval = 30 * time.Second

	// udpFlowSocketBufferSize is the OS-level SO_RCVBUF/SO_SNDBUF size
	// requested for each NAT entry's local socket - see listen/udp.go's
	// udpSocketBufferSize for why a plain [net.Dial] socket needs this at
	// all. Deliberately much smaller than listen's: this socket is
	// per-(subscriber, flow), and a long-lived share can have many NAT
	// entries live at once, so sizing each one for a single busy
	// aggregation point the way listen's one socket is would multiply
	// into real memory pressure.
	udpFlowSocketBufferSize = 1024 * 1024

	// udpKeepAlivePeriod and udpMaxIdleTimeout keep share's UDP-mode
	// data-plane QUIC connection to relay alive through long idle
	// stretches between flows, and let share notice one that's gone dark.
	// There's no application-level heartbeat on this connection (that's
	// the TCP control connection's job) - its liveness is entirely
	// quic-go's own PING-frame keepalive, which these enable (quic-go
	// disables keep-alives by default).
	udpKeepAlivePeriod = 15 * time.Second
	udpMaxIdleTimeout  = 30 * time.Second
)

// dialUDPConn dials relay's UDP-mode QUIC listener and performs the
// UDPAttach handshake identifying this connection as token's publisher,
// returning it ready for SendDatagram/ReceiveDatagram use. tlsConf is the
// same config Run already built for the TCP control connection - relay's
// QUIC listener authenticates with the same CA and requires the same
// client certificate.
func dialUDPConn(
	ctx context.Context,
	tlsConf *tls.Config,
	server hostport.HostPort,
	token proto.Token,
) (*quic.Conn, error) {
	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: udpKeepAlivePeriod,
		MaxIdleTimeout:  udpMaxIdleTimeout,
	}

	conn, err := quic.DialAddr(ctx, server.String(), tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("dial %s quic: %w", server, err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("open udp attach stream: %w", err)
	}

	attach := proto.UDPAttach{Role: proto.RolePublish, Token: token}
	if writeErr := proto.WriteUDPAttach(stream, attach); writeErr != nil {
		_ = conn.CloseWithError(0, "")
		return nil, writeErr
	}

	status, err := proto.ReadAck(stream)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	if err := status.Err(); err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}

	return conn, nil
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
// An entry owns no goroutine of its own beyond the pump reading its
// socket, which stops when that socket closes - so evicting one is just
// closing its conn.
type natEntry struct {
	conn net.Conn

	// lastActive is when this entry last carried traffic in either
	// direction, in Unix nanoseconds. It's atomic rather than guarded by
	// natTable's mutex because it's written on every packet, by every
	// live entry's pump goroutine at once: taking a table-wide lock there
	// serializes all of a busy share's flows against each other, which is
	// precisely the case this path is built for. Only the sweeper reads
	// it, and it tolerates a stale value - the idle timeout is already
	// coarse to within a whole udpSweepInterval.
	lastActive atomic.Int64
}

// touch records that this entry just carried traffic, keeping the sweeper
// from evicting it.
func (e *natEntry) touch() {
	e.lastActive.Store(time.Now().UnixNano())
}

// natTable is share's UDP-mode NAT: it demultiplexes datagrams arriving
// from potentially many subscribers' many local clients, each getting its
// own local socket dialed to the shared service. Their replies all go back
// through one uplink, so they coalesce with each other.
type natTable struct {
	uplink *dgram.Sender

	mu      sync.Mutex
	entries map[natKey]*natEntry
}

// runUDP is share's UDP-mode data plane: it reads relay-framed datagrams
// off quicConn, routes each to a per-(subscriber, flow) local UDP socket
// dialed to addr, and forwards that socket's replies back the same way.
// It runs until ctx is canceled, quicConn errors, or the control
// connection's heartbeat loop decides relay is dead.
func runUDP(ctx context.Context, control *tls.Conn, quicConn *quic.Conn, addr hostport.HostPort) error {
	table := &natTable{
		uplink:  dgram.NewSender(ctx, quicConn),
		entries: make(map[natKey]*natEntry),
	}
	defer table.closeAll()

	go table.sweep(ctx)

	heartbeatErr := make(chan error, 1)
	go func() {
		heartbeatErr <- runControlLoop(ctx, control, func(uint64) {})
		// The ReceiveDatagram below is the only thing keeping this share
		// alive, and no peer can hang up a QUIC connection - without this
		// close, a share whose relay has died sits there forever instead
		// of exiting.
		_ = quicConn.CloseWithError(0, "")
	}()

	for {
		data, err := quicConn.ReceiveDatagram(ctx)
		if err != nil {
			select {
			case hErr := <-heartbeatErr:
				return fmt.Errorf("control connection: %w", hErr)
			default:
				return fmt.Errorf("receive datagram: %w", err)
			}
		}

		// One datagram carries however many frames relay had waiting for
		// this publisher, across any number of subscribers and flows, so
		// every receive is a walk rather than a single decode - see
		// [proto.Batch].
		frames := proto.NewFrameReader(data)
		for {
			frame, ok := frames.Next()
			if !ok {
				break
			}
			table.deliver(ctx, addr, frame)
		}
	}
}

// deliver writes one frame's payload to the local socket dedicated to the
// (subscriber, flow) pair it names, dialing that socket if this is the
// first datagram seen for the pair.
func (t *natTable) deliver(ctx context.Context, addr hostport.HostPort, frame []byte) {
	sub, flow, payload, err := proto.DecodeFrame(frame)
	if err != nil {
		return // malformed frame from a misbehaving relay; drop it
	}

	entry, err := t.get(ctx, addr, sub, flow)
	if err != nil {
		return // local dial failed; drop this datagram, the next one retries
	}

	_, _ = entry.conn.Write(payload) // best-effort; a dead local socket just misses this one datagram
}

// get returns the NAT entry for key, dialing a fresh local socket and
// starting its reply-pump goroutine if this is the first datagram seen for
// that (subscriber, flow) pair.
func (t *natTable) get(
	ctx context.Context,
	addr hostport.HostPort,
	sub proto.SubscriberID,
	flow proto.FlowID,
) (*natEntry, error) {
	key := natKey{sub: sub, flow: flow}

	t.mu.Lock()
	entry, ok := t.entries[key]
	t.mu.Unlock()

	if ok {
		entry.touch()
		return entry, nil
	}

	var dialer net.Dialer
	local, err := dialer.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("dial %s for new flow: %w", addr, err)
	}

	// Best-effort, same rationale as listen/udp.go's SetReadBuffer call -
	// a clamped-down buffer just means less burst headroom.
	if udpConn, ok := local.(*net.UDPConn); ok {
		_ = udpConn.SetReadBuffer(udpFlowSocketBufferSize)
		_ = udpConn.SetWriteBuffer(udpFlowSocketBufferSize)
	}

	entry = &natEntry{conn: local}
	entry.touch()

	t.mu.Lock()
	t.entries[key] = entry
	t.mu.Unlock()

	go t.pump(entry, key)

	return entry, nil
}

// pump reads replies from a NAT entry's local socket and hands each,
// tagged with the header that routes it to the right subscriber's right
// local client, to the shared uplink sender - see [dgram.QueueDepth] for
// why reading and sending are kept apart. It runs until the local socket
// errors or closes, then evicts its own entry.
//
// Every NAT entry feeds the one sender rather than owning its own, so
// replies bound for different subscribers and different flows all pack
// into the same datagram. A share fronting a busy service has many entries
// live at once, which is exactly the case coalescing pays off in.
// It takes the entry rather than looking it up by key on every reply:
// marking an entry active is then one atomic store on memory the pump
// already holds, instead of a table-wide lock every other pump is
// contending for - see natEntry.lastActive.
func (t *natTable) pump(entry *natEntry, key natKey) {
	for {
		// Read straight into a pooled buffer, past the space its header
		// will occupy, so framing the reply below is a header write rather
		// than an allocation and a copy of the whole payload. The sender
		// returns the buffer once the frame has been packed.
		buf := proto.AcquireFrameBuffer()

		n, err := entry.conn.Read(proto.FramePayloadSpace(buf))
		if err != nil {
			proto.ReleaseFrameBuffer(buf)
			t.evict(key)
			return
		}

		if !proto.FinishFrame(buf, key.sub, key.flow, n) {
			proto.ReleaseFrameBuffer(buf) // larger than any datagram QUIC could carry
			continue
		}

		t.uplink.EnqueuePooled(buf)

		// Touched on replies too, so a service that pushes data without
		// being written to first still counts as active traffic. An entry
		// already evicted out from under this pump is about to have its
		// socket closed and the loop end, so the store is harmless.
		entry.touch()
	}
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
	cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()

	var stale []*natEntry
	t.mu.Lock()
	for key, entry := range t.entries {
		if entry.lastActive.Load() < cutoff {
			stale = append(stale, entry)
			delete(t.entries, key)
		}
	}
	t.mu.Unlock()

	for _, entry := range stale {
		_ = entry.conn.Close()
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
