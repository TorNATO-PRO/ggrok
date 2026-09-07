package relay

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// pendingRequestTimeout bounds how long relay waits for a publisher to
// fulfill a ControlRequestData before giving up on the subscriber's data
// connection that's waiting on it.
const pendingRequestTimeout = 10 * time.Second

// maxSessionPeers bounds subscriber bookkeeping and unpaired data sockets.
const maxSessionPeers = 1024

// notifyWriteTimeout bounds how long relay blocks writing a
// ControlSessionClosed frame to any one subscriber - see
// session.shutdown.
const notifyWriteTimeout = 5 * time.Second

// session is one active publisher and its currently-attached subscribers.
type session struct {
	mode      proto.Mode
	publisher *tls.Conn

	// ports is how many consecutive ports the publisher forwards. relay
	// knows nothing about which ports either side actually uses - only how
	// many there are, which is enough to turn away a subscriber whose
	// range is a different size and to reject a port index that names
	// nothing.
	ports uint16

	// publisherCert is the client certificate the publisher's control
	// connection authenticated with; AttachPublisherData requires the
	// publisher's data connections to present the same one.
	publisherCert *x509.Certificate

	// publisherPeer is publisherCert rendered for the admin snapshot, and
	// since is when the publisher registered. Both are set once at
	// construction and never written again, so neither needs mu.
	publisherPeer peerIdentity
	since         time.Time

	mu sync.Mutex

	// closed marks a session whose publisher has gone (see shutdown).
	// The registry has already dropped it by then, so this only matters
	// to a peer that looked the session up just before that happened and
	// is only now trying to join it.
	closed bool

	subscribers map[proto.SubscriberID]*subscriberConn
	nextSubID   proto.SubscriberID
	// Exact DER keys preserve byte-identical certificate binding. Counts allow
	// multiple control connections to register the same certificate.
	subscriberCerts map[string]int

	nextReqID uint64
	pending   map[uint64]*pendingRequest

	// streams is every forwarded connection currently being spliced, keyed
	// by the RequestID that created it. It is what lets an operator see a
	// tunnel that is working, as opposed to the "stream closed" log line,
	// which only says one existed - and for a tunnel up for hours, that
	// line may not appear during an entire operator session.
	streams map[uint64]*stream
}

// subscriberConn is what session tracks per attached subscriber: its control
// connection, which carries the heartbeat and the ControlSessionClosed frame
// that tells the subscriber its publisher has gone.
type subscriberConn struct {
	control *tls.Conn
	certKey string

	// peer is the subscriber's identity, captured at registration. It is
	// read for the admin snapshot without holding a certificate: certKey
	// above is raw DER kept for byte-identical binding, which is the wrong
	// shape to render, and re-parsing the leaf on every snapshot would be
	// work for no gain.
	peer peerIdentity
	// since is when this subscriber attached.
	since time.Time
}

// stream holds the metadata and counters shown in admin snapshots.
// The transport set owns eviction independently of session bookkeeping.
type stream struct {
	port    proto.PortIndex
	started time.Time
	counter *streamio.Counter
}

type pendingRequest struct {
	conn net.Conn
	// port is carried from AttachSubscriberData, which is where relay last
	// sees which port index the request names, through to
	// AttachPublisherData, which registers the stream and has only a
	// RequestID to go on.
	port  proto.PortIndex
	since time.Time
	timer *time.Timer
}

func newSession(mode proto.Mode, ports uint16, publisher *tls.Conn, publisherCert *x509.Certificate) *session {
	// Register always passes a live connection; the bookkeeping tests
	// construct a session without one, and an identity is not worth a panic.
	var addr net.Addr
	if publisher != nil {
		addr = publisher.RemoteAddr()
	}

	return &session{
		mode:            mode,
		ports:           ports,
		publisher:       publisher,
		publisherCert:   publisherCert,
		publisherPeer:   identityOf(publisherCert, addr),
		since:           time.Now(),
		subscribers:     make(map[proto.SubscriberID]*subscriberConn),
		pending:         make(map[uint64]*pendingRequest),
		subscriberCerts: make(map[string]int),
		streams:         make(map[uint64]*stream),
	}
}

// addSubscriber registers control under a freshly allocated SubscriberID.
// The returned release func removes it and must be called once the
// subscriber's control connection is done. ok is false if the session has
// already shut down, in which case nothing was registered and the caller
// must reject the subscriber.
func (s *session) addSubscriber(control *tls.Conn) (proto.SubscriberID, func(), bool) {
	cert, err := peerLeafCert(control)
	if err != nil {
		return 0, nil, false
	}
	certKey := string(cert.Raw)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || len(s.subscribers) >= maxSessionPeers {
		return 0, nil, false
	}

	id := s.nextSubID
	s.nextSubID++
	s.subscribers[id] = &subscriberConn{
		control: control,
		certKey: certKey,
		peer:    identityOf(cert, control.RemoteAddr()),
		since:   time.Now(),
	}
	s.subscriberCerts[certKey]++

	return id, func() { s.removeSubscriber(id) }, true
}

// removeSubscriber forgets id.
func (s *session) removeSubscriber(id proto.SubscriberID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subscribers[id]
	if !ok {
		return
	}
	delete(s.subscribers, id)
	s.subscriberCerts[sub.certKey]--
	if s.subscriberCerts[sub.certKey] == 0 {
		delete(s.subscriberCerts, sub.certKey)
	}
}

// addPending stashes conn under a freshly allocated RequestID and arms a
// timeout that closes conn and forgets the entry if claimPending never
// claims it within pendingRequestTimeout. ok is false if the session has
// already shut down - there is no publisher left to fulfill the request,
// so the caller must reject it rather than let conn wait out the timeout.
func (s *session) addPending(conn net.Conn, port proto.PortIndex) (uint64, bool) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return 0, false
	}
	cert, err := peerLeafCert(tlsConn)
	if err != nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || len(s.pending) >= maxSessionPeers {
		return 0, false
	}
	// A routing identifier alone must not bypass the subscriber control
	// registration and its certificate binding.
	if s.subscriberCerts[string(cert.Raw)] == 0 {
		return 0, false
	}
	id := s.nextReqID
	s.nextReqID++
	req := &pendingRequest{conn: conn, port: port, since: time.Now()}
	s.pending[id] = req
	// Install the timer before releasing mu so a concurrent claim can stop it.
	req.timer = time.AfterFunc(pendingRequestTimeout, func() { s.removePending(id) })

	return id, true
}

// removePending closes an unpaired connection on timeout or notification
// failure. It competes with pairing through claimPending, so only the winner
// owns the connection and an expired callback cannot close a paired stream.
func (s *session) removePending(id uint64) {
	conn, _, ok := s.claimPending(id)
	if ok {
		_ = conn.Close()
	}
}

// addStream records a paired stream for the life of its splice. ok is false
// if the session has already shut down, in which case the caller must not
// splice - beginShutdown has already closed everything it knew about, and a
// stream registered after it would never be closed by anyone.
func (s *session) addStream(reqID uint64, str *stream) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false
	}
	s.streams[reqID] = str

	return true
}

// removeStream forgets reqID's stream. It does not close anything: the splice
// that registered the stream owns both legs and has already closed them by
// the time this runs.
func (s *session) removeStream(reqID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.streams, reqID)
}

// shutdown ends the session for everyone still attached to it: it marks the
// session closed so nothing new can join, closes every subscriber data
// connection left waiting on a publisher that will never fulfill it, and
// tells every attached subscriber that the publisher is gone.
//
// Marking closed under the same lock as the snapshot is what makes this
// airtight: a subscriber that slips into addSubscriber between the
// registry dropping this session and this call would otherwise never be
// told, and would wait on the dead session forever - exactly the hang
// this frame exists to prevent.
//
// The pending connections are closed rather than left to their addPending
// timeouts, since a subscriber whose publisher just vanished shouldn't
// spend the rest of pendingRequestTimeout finding that out.
//
// Already-spliced streams are deliberately left alone. A publisher's control
// connection severing is the ordinary case reconnect exists for, and cutting
// every transfer in flight each time one flapped would be a far worse outcome
// than letting them finish against a session nobody can join any more. They
// end when either peer closes, and their removeStream is a no-op by then. The
// transport set still tracks them, so admin kick and CRL reload can close them.
//
// Subscriber control connections are closed after the notification: the
// peer can drain the written notification before observing EOF. One shared
// write deadline bounds the entire notification pass, and closing also evicts
// subscribers that ignore the session closure.
// It returns how many subscribers it notified.
func (s *session) shutdown() int {
	pending, controls := s.beginShutdown()
	for _, req := range pending {
		_ = req.conn.Close()
	}
	notifySessionClosed(controls)
	return len(controls)
}

// beginShutdown stops admission and takes ownership of pending requests
// under one lock. The caller does all network I/O after the
// lock is released; subscriber release callbacks still own their registrations.
func (s *session) beginShutdown() (map[uint64]*pendingRequest, []*tls.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	pending := s.pending
	s.pending = make(map[uint64]*pendingRequest)
	for _, req := range pending {
		req.timer.Stop()
	}

	controls := make([]*tls.Conn, 0, len(s.subscribers))
	for _, sub := range s.subscribers {
		controls = append(controls, sub.control)
	}
	return pending, controls
}

// notifySessionClosed shares one timeout across all subscriber notifications.
func notifySessionClosed(controls []*tls.Conn) {
	// Concurrent heartbeats also set deadlines. A hard transport close keeps
	// the shutdown bound independent of those updates and TLS write locks.
	timer := time.AfterFunc(notifyWriteTimeout, func() {
		for _, control := range controls {
			_ = control.NetConn().Close()
		}
	})
	defer timer.Stop()
	deadline := time.Now().Add(notifyWriteTimeout)
	for _, control := range controls {
		_ = control.SetWriteDeadline(deadline)
		_ = proto.WriteSessionClosed(control, proto.ReasonPublisherGone)
		_ = control.Close()
	}
}

// claimPending removes and returns id's pending connection and the port index
// it was opened for, if it's still there (not yet timed out or already
// claimed).
func (s *session) claimPending(id uint64) (net.Conn, proto.PortIndex, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.pending[id]
	if !ok {
		return nil, 0, false
	}
	delete(s.pending, id)
	req.timer.Stop()
	return req.conn, req.port, true
}
