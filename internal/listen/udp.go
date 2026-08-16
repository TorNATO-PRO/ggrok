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
	"tornato.dev/ggrok/v2/internal/dgram"
	"tornato.dev/ggrok/v2/internal/proto"
)

// udpSocketBufferSize is the OS-level SO_RCVBUF/SO_SNDBUF size requested
// for the local bind socket. Unlike quic-go's own UDP socket (which
// auto-tunes to several MB - see sys_conn_buffers.go), a plain
// [net.ListenUDP] socket keeps whatever small default the OS assigns. This
// socket is the single aggregation point for every local client's
// traffic on this listen instance, so a burst arriving faster than
// runUDP's read loop drains it can overflow that default and silently
// drop packets before the uplink sender's own queue-level backpressure
// ever gets a chance to matter - see [dgram.QueueDepth].
//
// 8MiB rather than something more modest because BenchmarkUDPBurstDrop
// (a burst of 8000x 512B datagrams arriving before any read) measured
// 3.6% loss at 4MiB but 0% at 8MiB on this machine's ~8MiB
// kern.ipc.maxsockbuf ceiling - and because SetReadBuffer/SetWriteBuffer
// are best-effort, a platform whose ceiling is lower (e.g. an untuned
// Linux host's net.core.rmem_max) just gets clamped down silently,
// same as quic-go's own request already does.
const udpSocketBufferSize = 8 * 1024 * 1024

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

// flowKey identifies one local client of this subscriber: the address it
// sends from, and which of listen's bound ports it sent to. The port is
// part of the identity because the same client talking to two ports of the
// range is two conversations with two different services, which have to
// stay apart on the way out and come back to the port they left from.
//
// Addresses are [netip.AddrPort] rather than *[net.UDPAddr]: it's comparable,
// so it keys byAddr directly, and the read/write paths that produce and
// consume it (ReadFromUDPAddrPort/WriteToUDPAddrPort) don't allocate -
// this table is consulted for every datagram, where a per-packet
// UDPAddr + string-key allocation is pure overhead.
type flowKey struct {
	addr netip.AddrPort
	port proto.PortIndex
}

// flowTable assigns a FlowID to each distinct local client seen on any of
// listen's bind sockets, and looks it back up to route a reply. FlowIDs
// are scoped to this one subscriber connection, so relay and share can
// tell this subscriber's local clients apart from every other
// subscriber's, and they're drawn from one space across every bound port,
// so a FlowID alone says which socket a reply goes back out of.
type flowTable struct {
	mu     sync.Mutex
	byAddr map[flowKey]proto.FlowID
	byFlow map[proto.FlowID]flowKey
	next   proto.FlowID
}

func newFlowTable() *flowTable {
	return &flowTable{
		byAddr: make(map[flowKey]proto.FlowID),
		byFlow: make(map[proto.FlowID]flowKey),
	}
}

// getOrCreate returns key's FlowID, assigning a fresh one the first time
// key is seen. ok is false when the table is full: FlowID's space is
// 65536 entries, and handing out an ID that's still bound to another live
// client would silently deliver one client's traffic to another - so a
// datagram from a brand-new client is dropped instead once no free ID
// remains.
func (t *flowTable) getOrCreate(key flowKey) (proto.FlowID, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if flow, ok := t.byAddr[key]; ok {
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
	t.byAddr[key] = flow
	t.byFlow[flow] = key

	return flow, true
}

// lookup returns the local client a FlowID was assigned to.
func (t *flowTable) lookup(flow proto.FlowID) (flowKey, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key, ok := t.byFlow[flow]
	return key, ok
}

// runUDP binds a local UDP socket on every port in addr and forwards
// datagrams both ways between them and quicConn, tagging each with the
// FlowID of the local client it came from (or is destined for) and the
// index of the port it arrived on. It runs until ctx is canceled, one of
// the local sockets errors, or the control connection's heartbeat loop
// decides relay is dead.
func runUDP(
	ctx context.Context,
	control *tls.Conn,
	quicConn *quic.Conn,
	addr hostport.Range,
	subID proto.SubscriberID,
	onListen func(net.Addr),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sockets, err := bindRangeUDP(addr)
	if err != nil {
		return err
	}
	defer closeAllUDP(sockets)

	if onListen != nil {
		for _, socket := range sockets {
			onListen(socket.LocalAddr())
		}
	}

	go func() {
		<-ctx.Done()
		closeAllUDP(sockets)
	}()

	// Closing the connection on the way out is what stops pumpDownlink,
	// which is otherwise parked in ReceiveDatagram on a connection no peer
	// will ever hang up on its own.
	defer func() { _ = quicConn.CloseWithError(0, "") }()

	flows := newFlowTable()
	go pumpDownlink(ctx, quicConn, sockets, flows)

	uplink := dgram.NewSender(ctx, quicConn)

	heartbeatErr := make(chan error, 1)
	go func() {
		heartbeatErr <- runControlLoop(ctx, control)
		// Nothing else would unblock the reads below: unlike TCP mode,
		// where the session ending eventually shows up as a failed data
		// dial, a UDP socket goes on happily accepting local datagrams
		// with nowhere left to send them. Canceling closes them (above).
		cancel()
	}()

	// One read loop per port, all feeding the one uplink sender, so
	// traffic from different ports coalesces into the same datagrams the
	// way traffic from different local clients already does. The channel
	// is deep enough for every loop, since canceling ctx fails them all at
	// once - see runTCP's acceptErr for the same reasoning.
	readErr := make(chan error, len(sockets))
	for i, socket := range sockets {
		port := proto.PortIndex(i)
		go func() {
			readErr <- pumpUplink(socket, uplink, flows, subID, port)
		}()
	}

	return ShutdownErr(ctx, heartbeatErr, <-readErr, "read")
}

// bindRangeUDP binds a UDP socket on every port in addr, unwinding the
// ones it already bound if any of them fails - a partially bound range is
// not a listen anyone asked for.
func bindRangeUDP(addr hostport.Range) ([]*net.UDPConn, error) {
	sockets := make([]*net.UDPConn, 0, addr.Len())
	for i := range addr.Len() {
		port, _ := addr.At(i) // i is bounded by Len, so this is always ok

		udpAddr, err := net.ResolveUDPAddr("udp", port.String())
		if err != nil {
			closeAllUDP(sockets)
			return nil, fmt.Errorf("resolve %s: %w", port, err)
		}

		socket, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			closeAllUDP(sockets)
			return nil, fmt.Errorf("listen on %s: %w", port, err)
		}

		// Best-effort: a smaller-than-requested buffer (the OS clamps
		// rather than errors on most platforms) just means less burst
		// headroom, not a failure worth aborting the listen for.
		_ = socket.SetReadBuffer(udpSocketBufferSize)
		_ = socket.SetWriteBuffer(udpSocketBufferSize)

		sockets = append(sockets, socket)
	}

	return sockets, nil
}

// closeAllUDP closes every socket, ignoring errors - it runs on teardown
// paths where there is nothing left to do about one.
func closeAllUDP(sockets []*net.UDPConn) {
	for _, socket := range sockets {
		_ = socket.Close()
	}
}

// pumpUplink reads local datagrams off socket - the port at index port of
// the session's range - frames each with the flow it belongs to, and hands
// it to the shared uplink sender. It returns once socket errors, which on
// an orderly shutdown means it was closed out from under it.
func pumpUplink(
	socket *net.UDPConn,
	uplink *dgram.Sender,
	flows *flowTable,
	subID proto.SubscriberID,
	port proto.PortIndex,
) error {
	for {
		// Read straight into a pooled buffer, past the space its header
		// will occupy, so framing the datagram below is a header write
		// rather than an allocation and a copy of the whole payload. The
		// sender returns the buffer once it's been sent.
		buf := proto.AcquireFrameBuffer()

		n, remoteAddr, err := socket.ReadFromUDPAddrPort(proto.FramePayloadSpace(buf))
		if err != nil {
			proto.ReleaseFrameBuffer(buf)
			return err
		}

		flow, ok := flows.getOrCreate(flowKey{addr: remoteAddr, port: port})
		if !ok {
			proto.ReleaseFrameBuffer(buf) // flow table full; drop rather than misroute
			continue
		}

		// subID is what listen believes it is; relay overwrites it with
		// the identity it authenticated this connection as, so this is for
		// whoever reads a packet capture, not for routing. The port, by
		// contrast, relay passes through untouched - it's the only thing
		// telling share which of its local ports this belongs to.
		if !proto.FinishFrame(buf, subID, flow, port, n) {
			proto.ReleaseFrameBuffer(buf) // larger than any datagram QUIC could carry
			continue
		}

		uplink.EnqueuePooled(buf)
	}
}

// pumpDownlink reads datagrams off quicConn and writes each frame packed
// inside back to the local client its FlowID names, out of the socket that
// client is talking to. It exits when quicConn errors.
func pumpDownlink(ctx context.Context, quicConn *quic.Conn, sockets []*net.UDPConn, flows *flowTable) {
	for {
		data, err := quicConn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		// One datagram carries however many frames relay had waiting for
		// this subscriber, so every receive is a walk rather than a single
		// decode - see [proto.Batch].
		frames := proto.NewFrameReader(data)
		for {
			frame, ok := frames.Next()
			if !ok {
				break
			}
			deliverDownlink(frame, sockets, flows)
		}
	}
}

// deliverDownlink writes one frame's payload back to the local client its
// FlowID was assigned to, dropping it if the frame is malformed or names a
// flow that has since gone.
func deliverDownlink(frame []byte, sockets []*net.UDPConn, flows *flowTable) {
	// The SubscriberID names this very subscriber - relay only sends a
	// frame down the connection it belongs to - so only the FlowID says
	// anything listen doesn't already know. The port in the header says
	// nothing either: the flow it belongs to was assigned on one specific
	// socket, and that binding, not the peer's header, is what decides
	// where the reply goes back out of.
	_, flow, _, payload, err := proto.DecodeFrame(frame)
	if err != nil {
		return // malformed frame from a misbehaving relay; drop it
	}

	key, ok := flows.lookup(flow)
	if !ok {
		return // unknown flow (e.g. already gone); drop it
	}

	_, _ = sockets[key.port].WriteToUDPAddrPort(payload, key.addr)
}
