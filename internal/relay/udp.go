package relay

import (
	"context"
	"crypto/cipher"
	"net"
	"sync"
	"sync/atomic"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/udpcrypto"
)

// udpReadBufferSize bounds a single incoming UDP datagram relay will
// accept before decoding - generous relative to any realistic path MTU.
const udpReadBufferSize = 64 * 1024

// routingIDSize mirrors proto.RoutingID's width, used to peel the
// cleartext routing prefix off an incoming packet before anything else.
const routingIDSize = 8

// udpRoute is relay's per-hop-endpoint UDP routing/crypto state: either
// the publisher's hop (relay<->share) or one subscriber's hop
// (relay<->that listen). It's looked up by RoutingID out of every
// incoming raw UDP packet, before any of it can be decrypted - relay
// mints one of these (and a fresh RoutingID to go with it) whenever a
// UDP-mode publisher registers or a UDP-mode subscriber attaches, via
// Registry.setupUDPRoute.
type udpRoute struct {
	routing proto.RoutingID
	sess    *session

	// isPublisher distinguishes which of session's two kinds of hop this
	// route is - not the same as testing subID against a sentinel, since
	// proto.SubscriberID's zero value is itself a validly minted ID.
	isPublisher bool
	subID       proto.SubscriberID

	sendAEAD cipher.AEAD
	sendCtr  atomic.Uint64

	recvAEAD cipher.AEAD
	recv     udpcrypto.ReplayWindow

	mu   sync.Mutex
	peer *net.UDPAddr // last-known source address; nil until a first packet arrives
}

// udpRouter is relay's single shared UDP socket, demultiplexing every
// UDP-mode session's traffic - both directions, every subscriber - by
// the cleartext RoutingID at the front of each packet (see
// internal/udpcrypto's package doc for why that prefix has to stay
// cleartext even though everything after it is encrypted).
type udpRouter struct {
	socket *net.UDPConn

	mu     sync.Mutex
	routes map[proto.RoutingID]*udpRoute
}

// newUDPRouter wraps socket - relay's shared UDP data-plane listener -
// with an empty route table.
func newUDPRouter(socket *net.UDPConn) *udpRouter {
	return &udpRouter{socket: socket, routes: make(map[proto.RoutingID]*udpRoute)}
}

// run reads and dispatches packets off ur.socket until ctx is canceled.
func (ur *udpRouter) run(ctx context.Context) {
	buf := make([]byte, udpReadBufferSize)
	for {
		n, peerAddr, err := ur.socket.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue // a single bad read shouldn't take the whole router down
		}

		packet := make([]byte, n) // buf is reused by the next ReadFromUDP
		copy(packet, buf[:n])
		ur.handlePacket(peerAddr, packet)
	}
}

// handlePacket decrypts one raw UDP packet via whichever route its
// cleartext RoutingID prefix names, decodes the Subscriber/PublisherFrame
// header inside, finds that datagram's other leg (the publisher's route
// for a subscriber's packet, or the named subscriber's route for a
// publisher's packet), and re-seals/forwards it there. Every failure mode
// here - unknown route, forged/corrupt packet, unknown subscriber, no
// route on the other leg yet - is a silent drop: a misbehaving peer or a
// stale route shouldn't be distinguishable on the wire from an ordinary
// lost UDP packet.
func (ur *udpRouter) handlePacket(peerAddr *net.UDPAddr, packet []byte) {
	if len(packet) < routingIDSize {
		return
	}

	var routing proto.RoutingID
	copy(routing[:], packet[:routingIDSize])

	ur.mu.Lock()
	route, ok := ur.routes[routing]
	ur.mu.Unlock()
	if !ok {
		return
	}

	plaintext, err := udpcrypto.Open(route.recvAEAD, &route.recv, packet)
	if err != nil {
		return
	}

	route.mu.Lock()
	route.peer = peerAddr
	route.mu.Unlock()

	pair, reencoded, ok := route.pairFor(plaintext)
	if !ok {
		return
	}

	pair.mu.Lock()
	dst := pair.peer
	pair.mu.Unlock()
	if dst == nil {
		return // haven't heard from that peer yet - nowhere to send
	}

	counter := pair.sendCtr.Add(1) - 1
	datagram := udpcrypto.Seal(pair.sendAEAD, pair.routing, counter, reencoded)
	_, _ = ur.socket.WriteToUDP(datagram, dst)
}

// pairFor decodes plaintext (already decrypted via route's own key) per
// route's kind, and resolves the datagram's other leg: the publisher's
// route for a subscriber's packet, or the named subscriber's route for a
// publisher's packet. ok is false if the frame is malformed or that leg
// isn't known (yet, or ever).
func (route *udpRoute) pairFor(plaintext []byte) (*udpRoute, []byte, bool) {
	if route.isPublisher {
		return route.publisherPair(plaintext)
	}
	return route.subscriberPair(plaintext)
}

// publisherPair is pairFor's publisher-route case: plaintext names which
// subscriber it's destined for.
func (route *udpRoute) publisherPair(plaintext []byte) (*udpRoute, []byte, bool) {
	sub, flow, payload, err := proto.DecodePublisherFrame(plaintext)
	if err != nil {
		return nil, nil, false
	}

	subRoute, ok := route.sess.subscriberUDPRoute(sub)
	if !ok {
		return nil, nil, false
	}

	return subRoute, proto.EncodeSubscriberFrame(flow, payload), true
}

// subscriberPair is pairFor's subscriber-route case: the destination is
// always this session's one publisher route.
func (route *udpRoute) subscriberPair(plaintext []byte) (*udpRoute, []byte, bool) {
	flow, payload, err := proto.DecodeSubscriberFrame(plaintext)
	if err != nil {
		return nil, nil, false
	}

	pair := route.sess.udpPublisherRoute
	if pair == nil {
		return nil, nil, false
	}

	return pair, proto.EncodePublisherFrame(route.subID, flow, payload), true
}

// addRoute builds a route's AEAD ciphers from sendKey/recvKey and
// registers it under routing (freshly minted by the caller - see
// Registry.setupUDPRoute).
func (ur *udpRouter) addRoute(
	routing proto.RoutingID,
	sess *session,
	isPublisher bool,
	subID proto.SubscriberID,
	sendKey, recvKey [udpcrypto.KeySize]byte,
) (*udpRoute, error) {
	sendAEAD, err := udpcrypto.NewAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	recvAEAD, err := udpcrypto.NewAEAD(recvKey)
	if err != nil {
		return nil, err
	}

	route := &udpRoute{
		routing:     routing,
		sess:        sess,
		isPublisher: isPublisher,
		subID:       subID,
		sendAEAD:    sendAEAD,
		recvAEAD:    recvAEAD,
	}

	ur.mu.Lock()
	ur.routes[routing] = route
	ur.mu.Unlock()

	return route, nil
}

// removeRoute forgets route, so its RoutingID is no longer routable -
// called when the session or subscriber it belongs to goes away.
func (ur *udpRouter) removeRoute(route *udpRoute) {
	ur.mu.Lock()
	delete(ur.routes, route.routing)
	ur.mu.Unlock()
}
