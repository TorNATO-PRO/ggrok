// Package relay is the rendezvous point between share (publisher) and
// listen (subscriber) connections: it pairs them by token. For TCP-mode
// sessions it splices their forwarded connections together (see
// registry.go's AttachSubscriberData/AttachPublisherData and udp.go's TCP
// counterparts don't exist - TCP-mode's data plane is plain spliced
// bytes). For UDP-mode sessions each party holds its own persistent QUIC
// connection to relay, and relay fans datagrams between them by the
// SubscriberID in the header of each one (see udp.go) - the one place
// relay loses "dumb pipe" purity, since it has to read that header to
// know where a datagram goes. The FlowID and PortIndex beside it mean
// nothing to relay and pass through untouched; only the two peers know
// which local client and which port they name.
package relay

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// errPublisherExists, errNoSuchSession, errModeMismatch, and
// errNotPublisherCert are the ways Register/Subscribe/AttachSubscriberData
// deliberately reject a peer. The first three map 1:1 to proto.AckStatus
// values.
var (
	errPublisherExists  = errors.New("token already has an active publisher")
	errNoSuchSession    = errors.New("no active session for this token")
	errModeMismatch     = errors.New("mode does not match this session's publisher")
	errPortsMismatch    = errors.New("port count does not match this session's publisher")
	errPortOutOfRange   = errors.New("port index is past the end of this session's range")
	errNotPublisherCert = errors.New("data connection certificate does not match this session's publisher")
)

// pendingRequestTimeout bounds how long relay waits for a publisher to
// fulfill a ControlRequestData before giving up on the subscriber's data
// connection that's waiting on it.
const pendingRequestTimeout = 10 * time.Second

// notifyWriteTimeout bounds how long relay blocks writing a
// ControlSessionClosed frame to any one subscriber - see
// session.shutdown.
const notifyWriteTimeout = 5 * time.Second

// sessionTagBytes is how much of a token's hash sessionAttr logs. Six
// bytes is far too little to attack the token behind it and far more than
// enough to keep concurrent sessions distinguishable in a log.
const sessionTagBytes = 6

// Registry holds every currently-active session, keyed by token.
type Registry struct {
	logger *slog.Logger

	mu       sync.Mutex
	sessions map[proto.Token]*session
}

// NewRegistry returns an empty Registry. logger records session lifecycle
// - who joined, who left, and what their forwarded connections carried; a
// nil one falls back to slog's default.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}

	return &Registry{logger: logger, sessions: make(map[proto.Token]*session)}
}

// peerAttr describes who is on the other end of conn for a log line: its
// network address, plus the Common Name of the certificate it
// authenticated with. The CN is the more durable of the two - relay
// requires and verifies a client certificate, so it names an identity the
// CA vouched for, where an address only says where a packet came from
// this time.
func peerAttr(conn net.Conn) slog.Attr {
	addr := slog.Any("addr", conn.RemoteAddr())

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return slog.Group("peer", addr)
	}

	cert, err := peerLeafCert(tlsConn)
	if err != nil {
		return slog.Group("peer", addr)
	}

	return slog.Group("peer", addr, slog.String("cn", cert.Subject.CommonName))
}

// sessionAttr identifies a session in the logs without ever writing its
// token there. The token is a bearer secret - anyone reading it out of a
// log file could subscribe to the session - so what gets logged is a
// truncated hash of it, which is enough to tie a publisher, its
// subscribers, and their streams together across log lines and nothing
// more.
func sessionAttr(token proto.Token) slog.Attr {
	sum := sha256.Sum256(token[:])
	return slog.String("session", hex.EncodeToString(sum[:sessionTagBytes]))
}

// Register adds control as token's publisher control connection and
// writes the corresponding ack to control. ports is how many consecutive
// ports the publisher forwards, which every subscriber then has to match.
// On success it returns an unregister func the caller must invoke (e.g.
// via defer) once control is done, so a later publish under the same token
// can succeed; the returned error is nil. On failure the returned func is
// nil and the error describes why - the caller owns closing control in
// that case.
func (r *Registry) Register(control *tls.Conn, token proto.Token, mode proto.Mode, ports uint16) (func(), error) {
	publisherCert, err := peerLeafCert(control)
	if err != nil {
		_ = proto.WriteAck(control, proto.AckNoSuchSession)
		return nil, fmt.Errorf("register publisher: %w", err)
	}

	r.mu.Lock()
	if _, exists := r.sessions[token]; exists {
		r.mu.Unlock()
		_ = proto.WriteAck(control, proto.AckPublisherExists)
		return nil, errPublisherExists
	}

	sess := newSession(mode, ports, control, publisherCert)
	r.sessions[token] = sess
	r.mu.Unlock()

	if err := proto.WriteAck(control, proto.AckOK); err != nil {
		r.mu.Lock()
		delete(r.sessions, token)
		r.mu.Unlock()
		return nil, fmt.Errorf("ack publisher: %w", err)
	}

	r.logger.Info("publisher registered",
		peerAttr(control), sessionAttr(token), slog.Any("mode", mode), slog.Int("ports", int(ports)))

	return func() {
		r.mu.Lock()
		delete(r.sessions, token)
		r.mu.Unlock()

		// Deleting the session above only stops peers that haven't looked
		// it up yet; everything already attached has to be told, or it
		// waits on a publisher that is never coming back.
		notified := sess.shutdown(proto.ReasonPublisherGone)

		r.logger.Info("publisher disconnected",
			peerAttr(control), sessionAttr(token), slog.Any("mode", mode), slog.Int("subscribers_notified", notified))
	}, nil
}

// Subscribe attaches control as a subscriber's control connection to
// token's session and writes the corresponding ack. ports is how many
// consecutive ports the subscriber binds, which must match what the
// session's publisher registered: the two sides address ports by index
// into their own ranges, so a subscriber binding more ports than the
// publisher forwards has ports that lead nowhere, and one binding fewer
// silently strands the publisher's tail. On success it returns the
// assigned SubscriberID and a release func the caller must invoke once
// control is done; the returned error is nil. On failure the returned func
// is nil and the error describes why - the caller owns closing control in
// that case.
func (r *Registry) Subscribe(
	control *tls.Conn,
	token proto.Token,
	mode proto.Mode,
	ports uint16,
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
	case sess.ports != ports:
		_ = proto.WriteAck(control, proto.AckPortsMismatch)
		return 0, nil, fmt.Errorf("%w: publisher has %d, subscriber has %d", errPortsMismatch, sess.ports, ports)
	}

	// Take the slot before acking, not after: a publisher unregistering
	// right now has to either see this subscriber (and notify it) or turn
	// it away here - never ack a subscriber into a session that has
	// already said its goodbyes.
	id, release, ok := sess.addSubscriber(control)
	if !ok {
		_ = proto.WriteAck(control, proto.AckNoSuchSession)
		return 0, nil, errNoSuchSession
	}

	if err := proto.WriteAck(control, proto.AckOK); err != nil {
		release()
		return 0, nil, fmt.Errorf("ack subscriber: %w", err)
	}

	r.logger.Info("subscriber attached",
		peerAttr(control), sessionAttr(token), slog.Any("mode", mode), slog.Any("sub", id))

	return id, func() {
		release()
		r.logger.Info("subscriber detached",
			peerAttr(control), sessionAttr(token), slog.Any("mode", mode), slog.Any("sub", id))
	}, nil
}

// sessionFor looks up token's session, if any.
func (r *Registry) sessionFor(token proto.Token) (*session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.sessions[token]
	return sess, ok
}

// AttachSubscriberData validates token (and that its session is TCP-mode,
// and that port names one of its ports), writes the corresponding ack to
// subConn, and - on success - registers subConn as pending under a freshly
// minted RequestID and asks the publisher to fulfill it via a
// ControlRequestData frame on its control connection, carrying port along
// so the publisher knows which of its local ports to dial. It does not
// wait for the publisher: AttachPublisherData completes the pairing once
// the publisher's data connection arrives, and a background timeout closes
// subConn if it never does.
//
// Callers must not close subConn after a nil-error return - ownership has
// passed to the pending entry (and from there, to whichever of
// AttachPublisherData's Splice or the timeout closes it). On a non-nil
// error, subConn is still the caller's to close; this func has not taken
// ownership of it.
func (r *Registry) AttachSubscriberData(subConn net.Conn, token proto.Token, port proto.PortIndex) error {
	sess, ok := r.sessionFor(token)
	switch {
	case !ok:
		_ = proto.WriteAck(subConn, proto.AckNoSuchSession)
		return errNoSuchSession
	case sess.mode != proto.ModeTCP:
		_ = proto.WriteAck(subConn, proto.AckModeMismatch)
		return errModeMismatch
	case uint16(port) >= sess.ports:
		// Subscribe already turned away any subscriber whose range is a
		// different size, so a port past the end here is a peer that made
		// the index up rather than an honest mismatch.
		_ = proto.WriteAck(subConn, proto.AckPortsMismatch)
		return fmt.Errorf("%w: port %d of %d", errPortOutOfRange, port, sess.ports)
	}

	// As in Subscribe, take the slot before acking, so a publisher
	// unregistering right now can't leave an acked connection waiting on
	// a request it will never make.
	reqID, ok := sess.addPending(subConn)
	if !ok {
		_ = proto.WriteAck(subConn, proto.AckNoSuchSession)
		return errNoSuchSession
	}

	if err := proto.WriteAck(subConn, proto.AckOK); err != nil {
		sess.removePending(reqID)
		return fmt.Errorf("ack subscriber data conn: %w", err)
	}

	if err := proto.WriteRequestData(sess.publisher, reqID, port); err != nil {
		sess.removePending(reqID)
		return fmt.Errorf("request publisher data conn: %w", err)
	}

	r.logger.Info("stream requested",
		peerAttr(subConn), sessionAttr(token), slog.Uint64("req", reqID), slog.Any("port", port))

	return nil
}

// AttachPublisherData pairs pubConn with the subscriber data connection
// waiting under reqID and splices them together, blocking until the
// forwarded connection ends (streamio.Splice closes both ends before
// returning). Returns an error without blocking, and without closing
// pubConn, if reqID is unknown - already timed out, already claimed, or
// forged; the caller owns closing pubConn in that case.
//
// pubConn must present the same client certificate the session's
// publisher registered with. The token alone can't gate this: every
// subscriber holds it too, and request IDs are guessable (sequential),
// so without the cert check a malicious subscriber could race the real
// publisher to claim another subscriber's pending connection and
// impersonate the shared service.
func (r *Registry) AttachPublisherData(token proto.Token, reqID uint64, pubConn *tls.Conn) error {
	sess, ok := r.sessionFor(token)
	if !ok {
		return errNoSuchSession
	}

	cert, err := peerLeafCert(pubConn)
	if err != nil {
		return fmt.Errorf("attach publisher data: %w", err)
	}
	if !cert.Equal(sess.publisherCert) {
		return errNotPublisherCert
	}

	subConn, ok := sess.claimPending(reqID)
	if !ok {
		return fmt.Errorf("unknown or expired request id %d", reqID)
	}

	started := time.Now()
	r.logger.Info(
		"stream paired",
		sessionAttr(token), slog.Uint64("req", reqID),
		slog.Group("subscriber", "addr", subConn.RemoteAddr()),
		slog.Group("publisher", "addr", pubConn.RemoteAddr()),
	)

	// Splice blocks for the whole life of the forwarded connection, so
	// this is the only moment relay can say what it carried - both legs
	// are closed by the time it returns.
	toSub, toPub := streamio.Splice(subConn, pubConn)

	r.logger.Info(
		"stream closed",
		sessionAttr(token), slog.Uint64("req", reqID),
		slog.Int64("bytes_to_subscriber", toSub), slog.Int64("bytes_to_publisher", toPub),
		slog.Duration("duration", time.Since(started).Round(time.Millisecond)),
	)

	return nil
}

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
	// connection authenticated with; AttachPublisherData and
	// AttachPublisherUDP require the publisher's data connection to
	// present the same one.
	publisherCert *x509.Certificate

	mu sync.Mutex

	// closed marks a session whose publisher has gone (see shutdown).
	// The registry has already dropped it by then, so this only matters
	// to a peer that looked the session up just before that happened and
	// is only now trying to join it.
	closed bool

	subscribers map[proto.SubscriberID]*subscriberConn
	nextSubID   proto.SubscriberID

	nextReqID uint64
	pending   map[uint64]net.Conn
}

// subscriberConn is what session tracks per attached subscriber: its
// control connection, used for liveness and (in UDP mode) as the source
// of the certificate its data-plane QUIC connection must match.
type subscriberConn struct {
	control *tls.Conn
}

func newSession(mode proto.Mode, ports uint16, publisher *tls.Conn, publisherCert *x509.Certificate) *session {
	s := &session{
		mode:          mode,
		ports:         ports,
		publisher:     publisher,
		publisherCert: publisherCert,
		subscribers:   make(map[proto.SubscriberID]*subscriberConn),
		pending:       make(map[uint64]net.Conn),
	}

	return s
}

// peerLeafCert returns conn's verified peer leaf certificate. relay's TLS
// config uses RequireAndVerifyClientCert, so by the time any post-handshake
// read has succeeded this is always present - but fail closed rather than
// panic if it somehow isn't.
func peerLeafCert(conn *tls.Conn) (*x509.Certificate, error) {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no peer certificate")
	}

	return certs[0], nil
}

// addSubscriber registers control under a freshly allocated SubscriberID.
// The returned release func removes it and must be called once the
// subscriber's control connection is done. ok is false if the session has
// already shut down, in which case nothing was registered and the caller
// must reject the subscriber.
func (s *session) addSubscriber(control *tls.Conn) (proto.SubscriberID, func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return 0, nil, false
	}

	id := s.nextSubID
	s.nextSubID++
	s.subscribers[id] = &subscriberConn{control: control}

	return id, func() { s.removeSubscriber(id) }, true
}

// removeSubscriber forgets id.
func (s *session) removeSubscriber(id proto.SubscriberID) {
	s.mu.Lock()
	delete(s.subscribers, id)
	s.mu.Unlock()
}

// addPending stashes conn under a freshly allocated RequestID and arms a
// timeout that closes conn and forgets the entry if claimPending never
// claims it within pendingRequestTimeout. ok is false if the session has
// already shut down - there is no publisher left to fulfill the request,
// so the caller must reject it rather than let conn wait out the timeout.
func (s *session) addPending(conn net.Conn) (uint64, bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, false
	}
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

	return id, true
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

// shutdown ends the session for everyone still attached to it: it marks
// the session closed so nothing new can join, closes every subscriber
// data connection left waiting on a publisher that will never fulfill it,
// closes every UDP-mode data-plane connection (the publisher's and every
// attached subscriber's - pumpPublisherDatagrams/pumpSubscriberDatagrams
// exit once their ReceiveDatagram call errors, which closing does), and
// sends every attached subscriber a ControlSessionClosed frame carrying
// reason.
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
// Subscriber control connections are deliberately left open: the
// subscriber tears its own end down on reading the frame, and closing
// here would risk resetting the connection out from under a frame the
// peer hasn't read yet. A subscriber that ignores the frame is no worse
// off than before it existed. The writes are best-effort and deadlined,
// so one wedged subscriber can't hold up the publisher's teardown or the
// notification owed to everyone behind it.
// It returns how many subscribers it notified.
func (s *session) shutdown(reason proto.SessionCloseReason) int {
	s.mu.Lock()
	s.closed = true

	pending := s.pending
	s.pending = make(map[uint64]net.Conn)

	controls := make([]*tls.Conn, 0, len(s.subscribers))
	for _, sub := range s.subscribers {
		controls = append(controls, sub.control)
	}

	s.mu.Unlock()

	for _, conn := range pending {
		_ = conn.Close()
	}

	for _, control := range controls {
		_ = control.SetWriteDeadline(time.Now().Add(notifyWriteTimeout))
		_ = proto.WriteSessionClosed(control, reason)
		_ = control.SetWriteDeadline(time.Time{})
	}

	return len(controls)
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
