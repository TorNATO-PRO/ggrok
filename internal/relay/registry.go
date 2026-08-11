// Package relay is the rendezvous point between share (publisher) and
// listen (subscriber) connections: it pairs them by token and, for
// TCP-mode sessions, splices their forwarded connections together. For
// UDP-mode sessions it demultiplexes AEAD-encrypted datagrams by a
// cleartext RoutingID (see internal/udpcrypto and udp.go) - the one place
// relay loses "dumb pipe" purity, since it has to read that routing
// header (and, for fan-out, the decrypted SubscriberID/FlowID header
// inside) to know where a datagram goes. See the "Fan-out design"
// section of docs/plans/tcp-udp-tunnel.md for the original rationale
// behind that header, which still holds even though the transport
// underneath it changed.
package relay

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
	"tornato.dev/ggrok/v2/internal/udpcrypto"
)

// errPublisherExists, errNoSuchSession, and errModeMismatch are the ways
// Register/Subscribe/AttachSubscriberData deliberately reject a peer.
// They map 1:1 to proto.AckStatus values.
var (
	errPublisherExists = errors.New("token already has an active publisher")
	errNoSuchSession   = errors.New("no active session for this token")
	errModeMismatch    = errors.New("mode does not match this session's publisher")
)

// pendingRequestTimeout bounds how long relay waits for a publisher to
// fulfill a ControlRequestData before giving up on the subscriber's data
// connection that's waiting on it.
const pendingRequestTimeout = 10 * time.Second

// Registry holds every currently-active session, keyed by token.
type Registry struct {
	udpRouter *udpRouter

	mu       sync.Mutex
	sessions map[proto.Token]*session
}

// NewRegistry returns an empty Registry. router is where Register and
// Subscribe wire up a UDP-mode session's data-plane routes; it may be nil
// if this relay will only ever serve TCP-mode sessions, in which case a
// UDP-mode Register/Subscribe fails cleanly instead of panicking.
func NewRegistry(router *udpRouter) *Registry {
	return &Registry{udpRouter: router, sessions: make(map[proto.Token]*session)}
}

// Register adds control as token's publisher control connection and
// writes the corresponding ack to control. On success it returns an
// unregister func the caller must invoke (e.g. via defer) once control is
// done, so a later publish under the same token can succeed; the returned
// error is nil. On failure the returned func is nil and the error
// describes why - the caller owns closing control in that case.
func (r *Registry) Register(control *tls.Conn, token proto.Token, mode proto.Mode) (func(), error) {
	r.mu.Lock()
	if _, exists := r.sessions[token]; exists {
		r.mu.Unlock()
		_ = proto.WriteAck(control, proto.AckPublisherExists)
		return nil, errPublisherExists
	}

	sess := newSession(mode, control)
	r.sessions[token] = sess
	r.mu.Unlock()

	if err := proto.WriteAck(control, proto.AckOK); err != nil {
		r.mu.Lock()
		delete(r.sessions, token)
		r.mu.Unlock()
		return nil, fmt.Errorf("ack publisher: %w", err)
	}

	if mode == proto.ModeUDP {
		route, err := r.setupUDPRoute(sess, control, token, true, 0)
		if err != nil {
			r.mu.Lock()
			delete(r.sessions, token)
			r.mu.Unlock()
			return nil, fmt.Errorf("set up publisher udp route: %w", err)
		}
		sess.udpPublisherRoute = route
	}

	return func() {
		r.mu.Lock()
		delete(r.sessions, token)
		r.mu.Unlock()

		if sess.udpPublisherRoute != nil {
			r.udpRouter.removeRoute(sess.udpPublisherRoute)
		}
	}, nil
}

// Subscribe attaches control as a subscriber's control connection to
// token's session and writes the corresponding ack. On success it returns
// the assigned SubscriberID and a release func the caller must invoke
// once control is done; the returned error is nil. On failure the
// returned func is nil and the error describes why - the caller owns
// closing control in that case.
func (r *Registry) Subscribe(
	control *tls.Conn,
	token proto.Token,
	mode proto.Mode,
) (proto.SubscriberID, func(), error) {
	r.mu.Lock()
	sess, ok := r.sessions[token]
	r.mu.Unlock()

	switch {
	case !ok:
		_ = proto.WriteAck(control, proto.AckNoSuchSession)
		return 0, nil, errNoSuchSession
	case sess.mode != mode:
		_ = proto.WriteAck(control, proto.AckModeMismatch)
		return 0, nil, errModeMismatch
	}

	if err := proto.WriteAck(control, proto.AckOK); err != nil {
		return 0, nil, fmt.Errorf("ack subscriber: %w", err)
	}

	id, release := sess.addSubscriber(control)

	if mode == proto.ModeUDP {
		route, err := r.setupUDPRoute(sess, control, token, false, id)
		if err != nil {
			release()
			return 0, nil, fmt.Errorf("set up subscriber udp route: %w", err)
		}
		sess.setSubscriberUDPRoute(id, route)

		release = func() {
			sess.removeSubscriber(id)
			r.udpRouter.removeRoute(route)
		}
	}

	return id, release, nil
}

// setupUDPRoute mints a fresh RoutingID, derives this hop's AEAD key pair
// off control's connection state, registers the route with the UDP
// router, and sends the RoutingID to control via a ControlUDPSession
// frame so the peer can derive the matching keys off its own end of the
// same TLS connection and start using it. No key material ever crosses
// the wire - RFC 5705's TLS exporter guarantees both ends compute the
// same value for the same (routing, token, direction) inputs.
//
// relay's own send direction is always this peer's downlink (relay ->
// peer) and its recv direction is always this peer's uplink (peer ->
// relay); the peer derives the same two keys under the same labels off
// its own end of this connection, with the directions swapped to match
// its own perspective - see share/listen's udp.go.
func (r *Registry) setupUDPRoute(
	sess *session,
	control *tls.Conn,
	token proto.Token,
	isPublisher bool,
	subID proto.SubscriberID,
) (*udpRoute, error) {
	if r.udpRouter == nil {
		return nil, errors.New("relay has no UDP listener configured")
	}

	routing, err := proto.NewRoutingID()
	if err != nil {
		return nil, fmt.Errorf("mint routing id: %w", err)
	}

	state := control.ConnectionState()

	sendKey, err := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionDownlink)
	if err != nil {
		return nil, err
	}
	recvKey, err := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionUplink)
	if err != nil {
		return nil, err
	}

	route, err := r.udpRouter.addRoute(routing, sess, isPublisher, subID, sendKey, recvKey)
	if err != nil {
		return nil, err
	}

	if err := proto.WriteUDPSession(control, routing); err != nil {
		r.udpRouter.removeRoute(route)
		return nil, fmt.Errorf("send udp session: %w", err)
	}

	return route, nil
}

// sessionFor looks up token's session, if any.
func (r *Registry) sessionFor(token proto.Token) (*session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.sessions[token]
	return sess, ok
}

// AttachSubscriberData validates token (and that its session is TCP-mode),
// writes the corresponding ack to subConn, and - on success - registers
// subConn as pending under a freshly minted RequestID and asks the
// publisher to fulfill it via a ControlRequestData frame on its control
// connection. It does not wait for the publisher: AttachPublisherData
// completes the pairing once the publisher's data connection arrives, and
// a background timeout closes subConn if it never does.
//
// Callers must not close subConn after a nil-error return - ownership has
// passed to the pending entry (and from there, to whichever of
// AttachPublisherData's Splice or the timeout closes it). On a non-nil
// error, subConn is still the caller's to close; this func has not taken
// ownership of it.
func (r *Registry) AttachSubscriberData(subConn net.Conn, token proto.Token) error {
	sess, ok := r.sessionFor(token)
	switch {
	case !ok:
		_ = proto.WriteAck(subConn, proto.AckNoSuchSession)
		return errNoSuchSession
	case sess.mode != proto.ModeTCP:
		_ = proto.WriteAck(subConn, proto.AckModeMismatch)
		return errModeMismatch
	}

	if err := proto.WriteAck(subConn, proto.AckOK); err != nil {
		return fmt.Errorf("ack subscriber data conn: %w", err)
	}

	reqID := sess.addPending(subConn)
	if err := proto.WriteRequestData(sess.publisher, reqID); err != nil {
		sess.removePending(reqID)
		return fmt.Errorf("request publisher data conn: %w", err)
	}

	return nil
}

// AttachPublisherData pairs pubConn with the subscriber data connection
// waiting under reqID and splices them together, blocking until the
// forwarded connection ends (streamio.Splice closes both ends before
// returning). Returns an error without blocking, and without closing
// pubConn, if reqID is unknown - already timed out, already claimed, or
// forged; the caller owns closing pubConn in that case.
func (r *Registry) AttachPublisherData(token proto.Token, reqID uint64, pubConn net.Conn) error {
	sess, ok := r.sessionFor(token)
	if !ok {
		return errNoSuchSession
	}

	subConn, ok := sess.claimPending(reqID)
	if !ok {
		return fmt.Errorf("unknown or expired request id %d", reqID)
	}

	streamio.Splice(subConn, pubConn)
	return nil
}

// session is one active publisher and its currently-attached subscribers.
type session struct {
	mode      proto.Mode
	publisher *tls.Conn

	mu          sync.Mutex
	subscribers map[proto.SubscriberID]*subscriberConn
	nextSubID   proto.SubscriberID

	nextReqID uint64
	pending   map[uint64]net.Conn

	// udpPublisherRoute is the publisher's relay<->share UDP data-plane
	// route - nil for a TCP-mode session, or a UDP-mode session before
	// setupUDPRoute finishes.
	udpPublisherRoute *udpRoute
}

// subscriberConn is what session tracks per attached subscriber: its
// control connection (liveness, and in UDP mode the source of its
// derived keys) and, in UDP mode only, the relay<->listen route its
// traffic is demultiplexed through.
type subscriberConn struct {
	control *tls.Conn
	udp     *udpRoute
}

func newSession(mode proto.Mode, publisher *tls.Conn) *session {
	return &session{
		mode:        mode,
		publisher:   publisher,
		subscribers: make(map[proto.SubscriberID]*subscriberConn),
		pending:     make(map[uint64]net.Conn),
	}
}

// addSubscriber registers control under a freshly allocated SubscriberID.
// The returned release func removes it and must be called once the
// subscriber's control connection is done.
func (s *session) addSubscriber(control *tls.Conn) (proto.SubscriberID, func()) {
	s.mu.Lock()
	id := s.nextSubID
	s.nextSubID++
	s.subscribers[id] = &subscriberConn{control: control}
	s.mu.Unlock()

	return id, func() { s.removeSubscriber(id) }
}

// removeSubscriber forgets id.
func (s *session) removeSubscriber(id proto.SubscriberID) {
	s.mu.Lock()
	delete(s.subscribers, id)
	s.mu.Unlock()
}

// setSubscriberUDPRoute records route as id's UDP data-plane route, if id
// is still a live subscriber (it may have already disconnected while its
// route was being set up).
func (s *session) setSubscriberUDPRoute(id proto.SubscriberID, route *udpRoute) {
	s.mu.Lock()
	if sc, ok := s.subscribers[id]; ok {
		sc.udp = route
	}
	s.mu.Unlock()
}

// subscriberUDPRoute returns id's UDP data-plane route, if it has one.
func (s *session) subscriberUDPRoute(id proto.SubscriberID) (*udpRoute, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sc, ok := s.subscribers[id]
	if !ok || sc.udp == nil {
		return nil, false
	}
	return sc.udp, true
}

// addPending stashes conn under a freshly allocated RequestID and arms a
// timeout that closes conn and forgets the entry if claimPending never
// claims it within pendingRequestTimeout.
func (s *session) addPending(conn net.Conn) uint64 {
	s.mu.Lock()
	id := s.nextReqID
	s.nextReqID++
	s.pending[id] = conn
	s.mu.Unlock()

	time.AfterFunc(pendingRequestTimeout, func() {
		s.mu.Lock()
		c, ok := s.pending[id]
		if ok {
			delete(s.pending, id)
		}
		s.mu.Unlock()

		if ok {
			_ = c.Close()
		}
	})

	return id
}

// removePending forgets id without claiming it, closing its connection -
// used when relay fails to even notify the publisher, since no timeout
// would otherwise fire correctly (the publisher never learns to ask).
func (s *session) removePending(id uint64) {
	s.mu.Lock()
	conn, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.mu.Unlock()

	if ok {
		_ = conn.Close()
	}
}

// claimPending removes and returns id's pending connection, if it's still
// there (not yet timed out or already claimed).
func (s *session) claimPending(id uint64) (net.Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	return conn, ok
}
