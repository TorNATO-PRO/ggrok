package listen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/udpcrypto"
)

// udpReadBufferSize is the max size of a single datagram read from the
// local socket, or off udpSession, before it's forwarded on.
const udpReadBufferSize = 64 * 1024

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

// flowTable assigns a FlowID to each distinct local remote address seen on
// listen's bind socket, and looks it back up to route a reply. FlowIDs are
// scoped to this one subscriber connection, so relay and share can tell
// this subscriber's local clients apart from every other subscriber's.
type flowTable struct {
	mu     sync.Mutex
	byAddr map[string]proto.FlowID
	byFlow map[proto.FlowID]*net.UDPAddr
	next   proto.FlowID
}

func newFlowTable() *flowTable {
	return &flowTable{
		byAddr: make(map[string]proto.FlowID),
		byFlow: make(map[proto.FlowID]*net.UDPAddr),
	}
}

// getOrCreate returns addr's FlowID, assigning a fresh one the first time
// addr is seen.
func (t *flowTable) getOrCreate(addr *net.UDPAddr) proto.FlowID {
	key := addr.String()

	t.mu.Lock()
	defer t.mu.Unlock()

	if flow, ok := t.byAddr[key]; ok {
		return flow
	}

	flow := t.next
	t.next++
	t.byAddr[key] = flow
	t.byFlow[flow] = addr

	return flow
}

// lookup returns the local remote address a FlowID was assigned to.
func (t *flowTable) lookup(flow proto.FlowID) (*net.UDPAddr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	addr, ok := t.byFlow[flow]
	return addr, ok
}

// runUDP binds addr as a local UDP socket and forwards datagrams both ways
// between it and udpSession, tagging each with the FlowID of the local
// client it came from (or is destined for). It runs until ctx is
// canceled, the local socket errors, or the control connection's
// heartbeat loop decides relay is dead.
func runUDP(ctx context.Context, control *tls.Conn, udpSession *udpcrypto.Session, addr hostport.HostPort) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return fmt.Errorf("resolve %s: %w", addr, err)
	}

	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer func() { _ = socket.Close() }()

	go func() {
		<-ctx.Done()
		_ = socket.Close()
	}()

	flows := newFlowTable()
	go pumpDownlink(udpSession, socket, flows)

	heartbeatErr := make(chan error, 1)
	go func() { heartbeatErr <- runControlLoop(ctx, control) }()

	buf := make([]byte, udpReadBufferSize)
	for {
		n, remoteAddr, err := socket.ReadFromUDP(buf)
		if err != nil {
			select {
			case hErr := <-heartbeatErr:
				return fmt.Errorf("control connection: %w", hErr)
			default:
				return fmt.Errorf("read: %w", err)
			}
		}

		flow := flows.getOrCreate(remoteAddr)

		if err := udpSession.Send(proto.EncodeSubscriberFrame(flow, buf[:n])); err != nil {
			return fmt.Errorf("send datagram: %w", err)
		}
	}
}

// pumpDownlink reads datagrams off udpSession, decodes the FlowID, and
// writes each payload back to the local remote address that flow was
// assigned to. It exits when udpSession errors.
func pumpDownlink(udpSession *udpcrypto.Session, socket *net.UDPConn, flows *flowTable) {
	buf := make([]byte, udpReadBufferSize)
	for {
		data, err := udpSession.Recv(buf)
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

		_, _ = socket.WriteToUDP(payload, remoteAddr)
	}
}
