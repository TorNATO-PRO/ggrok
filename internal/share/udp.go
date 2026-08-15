package share

import (
	"context"
	"crypto/tls"
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

	// udpFlowSocketBufferSize is the OS-level SO_RCVBUF/SO_SNDBUF size
	// requested for each NAT entry's local socket - see listen/udp.go's
	// udpSocketBufferSize for why a plain [net.Dial] socket needs this at
	// all. Deliberately much smaller than listen's: this socket is
	// per-(subscriber, flow), and a long-lived share can have many NAT
	// entries live at once, so sizing each one for a single busy
	// aggregation point the way listen's one socket is would multiply
	// into real memory pressure.
	udpFlowSocketBufferSize = 1024 * 1024

	// udpUplinkQueueDepth bounds how many locally-read replies natTable's
	// per-flow pump goroutine buffers before quicConn.SendDatagram
	// actually sends them. Without this, SendDatagram's blocking behavior
	// once quic-go's own internal send queue fills (see
	// internal/relay/udp.go's udpSender doc comment for the underlying
	// quic-go behavior this guards against) would stall the loop reading
	// that flow's local socket, letting its OS receive buffer overflow
	// and silently drop replies long before they ever reach quicConn.
	udpUplinkQueueDepth = 256

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
type natEntry struct {
	conn   net.Conn
	uplink chan []byte
	// cancel stops this entry's pumpUplink goroutine. Without it, that
	// goroutine would outlive the entry itself - runUDP's ctx only ends
	// when the whole publisher connection does, but individual entries
	// come and go throughout its life (idle sweep, a dead local socket),
	// so each eviction needs its own way to stop the goroutine feeding it.
	cancel     context.CancelFunc
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
// off quicConn, routes each to a per-(subscriber, flow) local UDP socket
// dialed to addr, and forwards that socket's replies back the same way.
// It runs until ctx is canceled, quicConn errors, or the control
// connection's heartbeat loop decides relay is dead.
func runUDP(ctx context.Context, control *tls.Conn, quicConn *quic.Conn, addr hostport.HostPort) error {
	table := &natTable{entries: make(map[natKey]*natEntry)}
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

		sub, flow, payload, err := proto.DecodePublisherFrame(data)
		if err != nil {
			continue // malformed frame from a misbehaving relay; drop it
		}

		entry, err := table.get(ctx, quicConn, addr, sub, flow)
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
	quicConn *quic.Conn,
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

	// Best-effort, same rationale as listen/udp.go's SetReadBuffer call -
	// a clamped-down buffer just means less burst headroom.
	if udpConn, ok := local.(*net.UDPConn); ok {
		_ = udpConn.SetReadBuffer(udpFlowSocketBufferSize)
		_ = udpConn.SetWriteBuffer(udpFlowSocketBufferSize)
	}

	entryCtx, cancel := context.WithCancel(ctx)
	entry = &natEntry{
		conn:       local,
		uplink:     make(chan []byte, udpUplinkQueueDepth),
		cancel:     cancel,
		lastActive: time.Now(),
	}

	t.mu.Lock()
	t.entries[key] = entry
	t.mu.Unlock()

	go pumpUplink(entryCtx, quicConn, entry.uplink)
	go t.pump(local, entry.uplink, key)

	return entry, nil
}

// pump reads replies from a NAT entry's local socket and hands each,
// tagged with the header that routes it to the right subscriber's right
// local client, to uplink for a separate goroutine to actually send - see
// udpUplinkQueueDepth's doc comment for why reading and sending are kept
// apart. It runs until the local socket errors or closes, then evicts its
// own entry.
func (t *natTable) pump(local net.Conn, uplink chan<- []byte, key natKey) {
	buf := make([]byte, udpReadBufferSize)
	for {
		n, err := local.Read(buf)
		if err != nil {
			t.evict(key)
			return
		}

		frame := proto.EncodePublisherFrame(key.sub, key.flow, buf[:n])
		select {
		case uplink <- frame:
		default: // uplink congested; drop rather than stall this read loop
		}

		t.touch(key)
	}
}

// pumpUplink drains uplink and sends each frame on quicConn, in its own
// goroutine so a SendDatagram call that blocks on quic-go's internal send
// queue never stalls the local-socket read loop feeding uplink. It exits
// when ctx is canceled.
func pumpUplink(ctx context.Context, quicConn *quic.Conn, uplink <-chan []byte) {
	for {
		select {
		case data := <-uplink:
			_ = quicConn.SendDatagram(data)
		case <-ctx.Done():
			return
		}
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
		entry.cancel()
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

	var stale []*natEntry
	t.mu.Lock()
	for key, entry := range t.entries {
		if entry.lastActive.Before(cutoff) {
			stale = append(stale, entry)
			delete(t.entries, key)
		}
	}
	t.mu.Unlock()

	for _, entry := range stale {
		entry.cancel()
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
