package listen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
)

// udpReadBufferSize is the max size of a single datagram read from the
// local socket before it's forwarded on.
const udpReadBufferSize = 64 * 1024

// udpSocketBufferSize is the OS-level SO_RCVBUF/SO_SNDBUF size requested
// for the local bind socket. Unlike quic-go's own UDP socket (which
// auto-tunes to several MB - see sys_conn_buffers.go), a plain
// net.ListenUDP socket keeps whatever small default the OS assigns. This
// socket is the single aggregation point for every local client's
// traffic on this listen instance, so a burst arriving faster than
// runUDP's read loop drains it can overflow that default and silently
// drop packets before udpUplinkQueueDepth's channel-level backpressure
// ever gets a chance to matter - see that constant's doc comment.
//
// 8MiB rather than something more modest because BenchmarkUDPBurstDrop
// (a burst of 8000x 512B datagrams arriving before any read) measured
// 3.6% loss at 4MiB but 0% at 8MiB on this machine's ~8MiB
// kern.ipc.maxsockbuf ceiling - and because SetReadBuffer/SetWriteBuffer
// are best-effort, a platform whose ceiling is lower (e.g. an untuned
// Linux host's net.core.rmem_max) just gets clamped down silently,
// same as quic-go's own request already does.
const udpSocketBufferSize = 8 * 1024 * 1024

// udpUplinkQueueDepth bounds how many locally-read datagrams runUDP
// buffers before quicConn.SendDatagram actually sends them. Without this,
// SendDatagram's blocking behavior once quic-go's own internal send queue
// fills (see internal/relay/udp.go's udpSender doc comment for the
// underlying quic-go behavior this guards against) would stall the loop
// reading the local socket, letting the OS's UDP receive buffer for that
// socket overflow and silently drop packets long before they ever reach
// quicConn.
const udpUplinkQueueDepth = 256

// udpKeepAlivePeriod and udpMaxIdleTimeout keep listen's UDP-mode
// data-plane QUIC connection to relay alive through long idle stretches
// between flows, and let listen notice one that's gone dark. There's no
// application-level heartbeat on this connection (that's the TCP control
// connection's job) - its liveness is entirely quic-go's own PING-frame
// keepalive, which these enable (quic-go disables keep-alives by
// default).
const (
	udpKeepAlivePeriod = 15 * time.Second
	udpMaxIdleTimeout  = 30 * time.Second
)

// readSubscriberID reads the frame relay sends immediately after acking a
// UDP-mode Subscribe - normally a ControlSubscriberID naming the id this
// subscriber presents in its own UDPAttach handshake, but occasionally a
// ControlSessionClosed instead: the publisher can go away in the exact
// window between relay acking this subscription and sending that id, in
// which case the first frame to arrive is the session's obituary, not the
// id.
func readSubscriberID(control *tls.Conn) (proto.SubscriberID, error) {
	typ, payload, err := proto.ReadControlFrame(control)
	if err != nil {
		return 0, fmt.Errorf("read subscriber id: %w", err)
	}

	if typ == proto.ControlSessionClosed {
		return 0, sessionClosedErr(payload)
	}
	if typ != proto.ControlSubscriberID {
		return 0, fmt.Errorf("expected ControlSubscriberID, got frame type %d", typ)
	}

	return proto.ReadSubscriberID(payload)
}

// dialUDPConn dials relay's UDP-mode QUIC listener and performs the
// UDPAttach handshake identifying this connection as subscriber id's data
// plane, returning it ready for SendDatagram/ReceiveDatagram use. tlsConf
// is the same config Run already built for the TCP control connection -
// relay's QUIC listener authenticates with the same CA and requires the
// same client certificate.
func dialUDPConn(
	ctx context.Context,
	tlsConf *tls.Config,
	server hostport.HostPort,
	token proto.Token,
	id proto.SubscriberID,
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

	attach := proto.UDPAttach{Role: proto.RoleSubscribe, Token: token, SubscriberID: id}
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

// flowTable assigns a FlowID to each distinct local remote address seen on
// listen's bind socket, and looks it back up to route a reply. FlowIDs are
// scoped to this one subscriber connection, so relay and share can tell
// this subscriber's local clients apart from every other subscriber's.
//
// Addresses are [netip.AddrPort] rather than *[net.UDPAddr]: it's comparable,
// so it keys byAddr directly, and the read/write paths that produce and
// consume it (ReadFromUDPAddrPort/WriteToUDPAddrPort) don't allocate -
// this table is consulted for every datagram, where a per-packet
// UDPAddr + string-key allocation is pure overhead.
type flowTable struct {
	mu     sync.Mutex
	byAddr map[netip.AddrPort]proto.FlowID
	byFlow map[proto.FlowID]netip.AddrPort
	next   proto.FlowID
}

func newFlowTable() *flowTable {
	return &flowTable{
		byAddr: make(map[netip.AddrPort]proto.FlowID),
		byFlow: make(map[proto.FlowID]netip.AddrPort),
	}
}

// getOrCreate returns addr's FlowID, assigning a fresh one the first time
// addr is seen. ok is false when the table is full: FlowID's space is
// 65536 entries, and handing out an ID that's still bound to another live
// address would silently deliver one client's traffic to another - so a
// datagram from a brand-new address is dropped instead once no free ID
// remains.
func (t *flowTable) getOrCreate(addr netip.AddrPort) (proto.FlowID, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if flow, ok := t.byAddr[addr]; ok {
		return flow, true
	}

	// next is only a hint: it may point at an ID still in use once the
	// counter has wrapped, so probe forward until a free one turns up.
	const flowIDSpace = 1 << 16
	if len(t.byFlow) >= flowIDSpace {
		return 0, false
	}
	for {
		if _, taken := t.byFlow[t.next]; !taken {
			break
		}
		t.next++
	}

	flow := t.next
	t.next++
	t.byAddr[addr] = flow
	t.byFlow[flow] = addr

	return flow, true
}

// lookup returns the local remote address a FlowID was assigned to.
func (t *flowTable) lookup(flow proto.FlowID) (netip.AddrPort, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	addr, ok := t.byFlow[flow]
	return addr, ok
}

// runUDP binds addr as a local UDP socket and forwards datagrams both ways
// between it and quicConn, tagging each with the FlowID of the local
// client it came from (or is destined for). It runs until ctx is
// canceled, the local socket errors, or the control connection's
// heartbeat loop decides relay is dead.
func runUDP(
	ctx context.Context,
	control *tls.Conn,
	quicConn *quic.Conn,
	addr hostport.HostPort,
	onListen func(net.Addr),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return fmt.Errorf("resolve %s: %w", addr, err)
	}

	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer func() { _ = socket.Close() }()

	// Best-effort: a smaller-than-requested buffer (the OS clamps rather
	// than errors on most platforms) just means less burst headroom, not
	// a failure worth aborting the listen for.
	_ = socket.SetReadBuffer(udpSocketBufferSize)
	_ = socket.SetWriteBuffer(udpSocketBufferSize)

	if onListen != nil {
		onListen(socket.LocalAddr())
	}

	go func() {
		<-ctx.Done()
		_ = socket.Close()
	}()

	// Closing the connection on the way out is what stops pumpDownlink,
	// which is otherwise parked in ReceiveDatagram on a connection no peer
	// will ever hang up on its own.
	defer func() { _ = quicConn.CloseWithError(0, "") }()

	flows := newFlowTable()
	go pumpDownlink(ctx, quicConn, socket, flows)

	uplink := make(chan []byte, udpUplinkQueueDepth)
	go pumpUplink(ctx, quicConn, uplink)

	heartbeatErr := make(chan error, 1)
	go func() {
		heartbeatErr <- runControlLoop(ctx, control)
		// Nothing else would unblock the read below: unlike TCP mode,
		// where the session ending eventually shows up as a failed data
		// dial, a UDP socket goes on happily accepting local datagrams
		// with nowhere left to send them. Canceling closes it (above).
		cancel()
	}()

	buf := make([]byte, udpReadBufferSize)
	for {
		n, remoteAddr, err := socket.ReadFromUDPAddrPort(buf)
		if err != nil {
			return ShutdownErr(ctx, heartbeatErr, err, "read")
		}

		flow, ok := flows.getOrCreate(remoteAddr)
		if !ok {
			continue // flow table full; drop rather than misroute
		}

		frame := proto.EncodeSubscriberFrame(flow, buf[:n])
		select {
		case uplink <- frame:
		default: // uplink congested; drop rather than stall this read loop
		}
	}
}

// pumpUplink drains uplink and sends each frame on quicConn, in its own
// goroutine so a SendDatagram call that blocks on quic-go's internal send
// queue never stalls runUDP's local-socket read loop - see
// udpUplinkQueueDepth's doc comment for why that matters. It exits when
// ctx is canceled.
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

// pumpDownlink reads datagrams off quicConn, decodes the FlowID, and
// writes each payload back to the local remote address that flow was
// assigned to. It exits when quicConn errors.
func pumpDownlink(ctx context.Context, quicConn *quic.Conn, socket *net.UDPConn, flows *flowTable) {
	for {
		data, err := quicConn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		flow, payload, err := proto.DecodeSubscriberFrame(data)
		if err != nil {
			continue // malformed frame from a misbehaving relay; drop it
		}

		remoteAddr, ok := flows.lookup(flow)
		if !ok {
			continue // unknown flow (e.g. already gone); drop it
		}

		_, _ = socket.WriteToUDPAddrPort(payload, remoteAddr)
	}
}
