package listen

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
)

// udpReadBufferSize is the max size of a single datagram read from the
// local socket before it's forwarded through the tunnel.
const udpReadBufferSize = 64 * 1024

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
// between it and conn, tagging each with the FlowID of the local client it
// came from (or is destined for).
func runUDP(ctx context.Context, conn *quic.Conn, addr hostport.HostPort) error {
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
	go pumpDownlink(ctx, conn, socket, flows)

	buf := make([]byte, udpReadBufferSize)
	for {
		n, remoteAddr, err := socket.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		flow := flows.getOrCreate(remoteAddr)

		if err := conn.SendDatagram(proto.EncodeSubscriberFrame(flow, buf[:n])); err != nil {
			return fmt.Errorf("send datagram: %w", err)
		}
	}
}

// pumpDownlink reads datagrams off conn, decodes the FlowID, and writes
// each payload back to the local remote address that flow was assigned
// to. It exits when ctx is done or conn errors.
func pumpDownlink(ctx context.Context, conn *quic.Conn, socket *net.UDPConn, flows *flowTable) {
	for {
		data, err := conn.ReceiveDatagram(ctx)
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
