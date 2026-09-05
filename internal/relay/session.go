package relay

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
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
}

// subscriberConn is what session tracks per attached subscriber: its control
// connection, which carries the heartbeat and the ControlSessionClosed frame
// that tells the subscriber its publisher has gone.
type subscriberConn struct {
	control *tls.Conn
	certKey string
}

type pendingRequest struct {
	conn  net.Conn
	timer *time.Timer
}

func newSession(mode proto.Mode, ports uint16, publisher *tls.Conn, publisherCert *x509.Certificate) *session {
	return &session{
		mode:            mode,
		ports:           ports,
		publisher:       publisher,
		publisherCert:   publisherCert,
		subscribers:     make(map[proto.SubscriberID]*subscriberConn),
		pending:         make(map[uint64]*pendingRequest),
		subscriberCerts: make(map[string]int),
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
	s.subscribers[id] = &subscriberConn{control: control, certKey: certKey}
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
func (s *session) addPending(conn net.Conn) (uint64, bool) {
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
	req := &pendingRequest{conn: conn}
	s.pending[id] = req
	// Install the timer before releasing mu so a concurrent claim can stop it.
	req.timer = time.AfterFunc(pendingRequestTimeout, func() { s.removePending(id) })

	return id, true
}

// removePending closes an unpaired connection on timeout or notification
// failure. It competes with pairing through claimPending, so only the winner
// owns the connection and an expired callback cannot close a paired stream.
func (s *session) removePending(id uint64) {
	conn, ok := s.claimPending(id)
	if ok {
		_ = conn.Close()
	}
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

// claimPending removes and returns id's pending connection, if it's still
// there (not yet timed out or already claimed).
func (s *session) claimPending(id uint64) (net.Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.pending[id]
	if !ok {
		return nil, false
	}
	delete(s.pending, id)
	req.timer.Stop()
	return req.conn, true
}
