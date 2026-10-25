// Package relay is the rendezvous point between share (publisher) and
// listen (subscriber) connections: it pairs them by SessionID and splices
// their forwarded connections together (see AttachSubscriberData and
// AttachPublisherData).
//
// relay is a dumb pipe by construction. A session's SessionID is derived
// from its token, and the keys protecting the forwarded bytes are derived
// separately from that same token - so relay holds enough to route a
// session and not enough to read one. What it splices is ciphertext
// (see proto.EncryptedConn), and the only things it interprets are the
// Hello and Attach that name the session and the control frames that keep
// it alive.
package relay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// errPublisherExists, errNoSuchSession, errModeMismatch, and
// errNotPublisherCert are the ways Register/Subscribe/AttachSubscriberData
// deliberately reject a peer. The first three map 1:1 to proto.AckStatus
// values.
var (
	errPublisherExists  = errors.New("session already has an active publisher")
	errNoSuchSession    = errors.New("no active session for this identifier")
	errSessionKilled    = errors.New("session was ended by an operator")
	errAmbiguousTag     = errors.New("session tag matches more than one session")
	errModeMismatch     = errors.New("mode does not match this session's publisher")
	errPortsMismatch    = errors.New("port count does not match this session's publisher")
	errPortOutOfRange   = errors.New("port index is past the end of this session's range")
	errNotPublisherCert = errors.New("data connection certificate does not match this session's publisher")
)

// sessionAttr identifies a session in the logs without writing the whole
// SessionID there. The SessionID is what a peer presents to attach to a
// session, so anyone reading one out of a log file could take a subscriber
// slot on a live tunnel - they could not decrypt any of it, but that is a
// property of the data keys, not a reason to publish the identifier. A
// truncated form ties a publisher, its subscribers and their streams
// together across log lines and does nothing else.
func sessionAttr(id proto.SessionID) slog.Attr {
	return slog.String("session", id.LogTag())
}

// Registry holds every currently-active session, keyed by SessionID.
type Registry struct {
	logger *slog.Logger

	mu       sync.Mutex
	sessions map[proto.SessionID]*session

	// killed is every SessionID an operator has ended with Kill. It is what
	// makes a kill outlast the connection it closed: a publisher whose
	// control connection simply drops cannot tell that from a flap and comes
	// straight back, so ending a session for good means refusing the next
	// registration too, not just severing this one.
	//
	// It only grows, and only in memory. A relay restart forgets every kill,
	// which is the honest scope of the feature - a permanent decision about a
	// peer is a revocation, and lives in the CA rather than here. Growth is
	// bounded by how many sessions an operator kills by hand; each entry is a
	// 32-byte key.
	killed map[proto.SessionID]struct{}
}

// NewRegistry returns an empty Registry. logger records session lifecycle
// - who joined, who left, and what their forwarded connections carried; a
// nil one falls back to slog's default.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}

	return &Registry{
		logger:   logger,
		sessions: make(map[proto.SessionID]*session),
		killed:   make(map[proto.SessionID]struct{}),
	}
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

// peerIdentity is who a connection belongs to, in the form an operator reads
// and acts on. It is peerAttr's content captured as data rather than as a log
// record, because the same three facts answer "who is attached" in a snapshot
// and "which connections does this serial cover" for a CRL reload.
//
// Serial is rendered in ca.SerialTextBase, the same form ca crl writes and
// verifyNotRevoked compares, so a serial read off a listing can be pasted
// straight into a revoked file.
type peerIdentity struct {
	cn     string
	serial string
	addr   string
}

// identityOf renders cert and addr as a peerIdentity. A nil cert yields the
// address alone - relay requires and verifies a client certificate, so that
// should not happen, but a snapshot is not worth a panic.
func identityOf(cert *x509.Certificate, addr net.Addr) peerIdentity {
	id := peerIdentity{}
	if addr != nil {
		id.addr = addr.String()
	}
	if cert != nil {
		id.cn = cert.Subject.CommonName
		id.serial = cert.SerialNumber.Text(ca.SerialTextBase)
	}

	return id
}

// Register adds control as hello.SessionID's publisher control connection and
// writes the corresponding ack to control. hello.Ports is how many
// consecutive ports the publisher forwards, which every subscriber then has
// to match. On success it returns an unregister func the caller must invoke
// (e.g. via defer) once control is done, so a later publish under the same
// SessionID can succeed; the returned error is nil. On failure the returned
// func is nil and the error describes why - the caller owns closing control in
// that case.
//
// The slot is only ever handed to a peer that proves the session is its own.
// A SessionID is not a credential - it's a pure function of the publisher's
// session public key, and every subscriber holds it - so without the claim
// below, any token holder could wait for the real publisher's connection to
// sever and register in its place, serving its own service to every other
// subscriber while the displaced publisher was locked out of its own tunnel.
func (r *Registry) Register(control *tls.Conn, hello proto.Hello) (func(), error) {
	sessionID, mode, ports := hello.SessionID, hello.Mode, hello.Ports

	publisherCert, err := peerLeafCert(control)
	if err != nil {
		_ = proto.WriteAck(control, proto.AckDenied)
		return nil, fmt.Errorf("register publisher: %w", err)
	}

	// Prove first, claim second. Running the challenge before the occupancy
	// check also keeps relay from telling an unauthenticated claimant
	// whether a session exists at all.
	if err := proto.VerifyPublishClaim(control, hello); err != nil {
		_ = proto.WriteAck(control, proto.AckDenied)
		return nil, fmt.Errorf("register publisher: %w", err)
	}

	r.mu.Lock()
	// Checked here rather than before the claim, for the same reason the
	// occupancy check is: a claimant that cannot prove the session is its own
	// learns nothing about it, including whether it was killed. AckDenied is
	// terminal on the peer side (see peer.retryable), so the publisher this
	// turns away prints the refusal and exits instead of reconnecting - which
	// is what makes a kill outlast the connection it closed.
	if _, killed := r.killed[sessionID]; killed {
		r.mu.Unlock()
		_ = proto.WriteAck(control, proto.AckDenied)
		return nil, fmt.Errorf("register publisher: %w", errSessionKilled)
	}
	if _, exists := r.sessions[sessionID]; exists {
		r.mu.Unlock()
		_ = proto.WriteAck(control, proto.AckPublisherExists)
		return nil, errPublisherExists
	}

	sess := newSession(mode, ports, control, publisherCert)
	r.sessions[sessionID] = sess
	r.mu.Unlock()

	if err := proto.WriteAck(control, proto.AckOK); err != nil {
		r.mu.Lock()
		delete(r.sessions, sessionID)
		r.mu.Unlock()
		sess.shutdown()
		return nil, fmt.Errorf("ack publisher: %w", err)
	}

	r.logger.Info("publisher registered",
		peerAttr(control), sessionAttr(sessionID), slog.Any("mode", mode), slog.Int("ports", int(ports)))

	return func() {
		r.mu.Lock()
		delete(r.sessions, sessionID)
		r.mu.Unlock()

		// Deleting the session above only stops peers that haven't looked
		// it up yet; everything already attached has to be told, or it
		// waits on a publisher that is never coming back.
		notified := sess.shutdown()

		r.logger.Info("publisher disconnected",
			peerAttr(control), sessionAttr(sessionID),
			slog.Any("mode", mode), slog.Int("subscribers_notified", notified))
	}, nil
}

// Subscribe attaches control as a subscriber's control connection to
// hello.SessionID's session and writes the corresponding ack. hello.Ports is
// how many consecutive ports the subscriber binds, which must match what the
// session's publisher registered: the two sides address ports by index
// into their own ranges, so a subscriber binding more ports than the
// publisher forwards has ports that lead nowhere, and one binding fewer
// silently strands the publisher's tail. On success it returns the
// assigned SubscriberID and a release func the caller must invoke once
// control is done; the returned error is nil. On failure the returned func
// is nil and the error describes why - the caller owns closing control in
// that case.
//
// There is no counterpart to Register's publish claim here, and deliberately
// so: holding the SessionID is what a subscriber's authorization consists of,
// and everything it can then reach is sealed under a secret relay does not
// have.
func (r *Registry) Subscribe(control *tls.Conn, hello proto.Hello) (proto.SubscriberID, func(), error) {
	sessionID, mode, ports := hello.SessionID, hello.Mode, hello.Ports

	sess, ok := r.sessionFor(sessionID)

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
		peerAttr(control), sessionAttr(sessionID), slog.Any("mode", mode), slog.Any("sub", id))

	return id, func() {
		release()
		r.logger.Info("subscriber detached",
			peerAttr(control), sessionAttr(sessionID), slog.Any("mode", mode), slog.Any("sub", id))
	}, nil
}

// Kill ends the session an admin snapshot showed as tag and refuses that
// SessionID for the rest of this relay's life. It returns how many
// subscribers were notified.
//
// Closing connections alone cannot do this: a closed connection is
// indistinguishable from a severed one, so share reconnects through it by
// design (see peer.retryable) - which is why admin kick, which did only that,
// was retired. Kill removes the session, closes
// the publisher's control connection, tells the subscribers, and remembers the
// SessionID - so the reconnect that follows is answered with AckDenied, which
// the publisher treats as terminal and exits on.
//
// What it does not do is stop the peer. The ban is keyed on the SessionID,
// which is a function of the session key, so the same certificate can start a
// fresh share under a new key and be a session this has never heard of.
// Stopping an identity rather than a session is what ca revoke is for.
//
// Streams already spliced are left running, exactly as an ordinary publisher
// disconnect leaves them (see session.shutdown). In practice they end within a
// reconnect attempt, because the publisher that owns both of their ends is on
// its way to exiting.
func (r *Registry) Kill(tag string) (int, error) {
	r.mu.Lock()

	var (
		found   proto.SessionID
		sess    *session
		matches int
	)
	for id, candidate := range r.sessions {
		if id.LogTag() == tag {
			found, sess, matches = id, candidate, matches+1
		}
	}

	switch {
	case matches == 0:
		r.mu.Unlock()
		return 0, fmt.Errorf("%w: %s", errNoSuchSession, tag)
	case matches > 1:
		// A tag is a truncation, so two live sessions sharing one is
		// possible even though it is vanishingly unlikely. Refusing beats
		// killing whichever the map happened to yield last.
		r.mu.Unlock()
		return 0, fmt.Errorf("%w: %s", errAmbiguousTag, tag)
	}

	r.killed[found] = struct{}{}
	delete(r.sessions, found)
	r.mu.Unlock()

	// Closing the publisher's control connection is what ends the session
	// from its side; the ban above is what keeps it ended. Order matters
	// only in that both happen before this returns, so the operator's
	// "killed" is true by the time they read it.
	_ = sess.publisher.Close()
	notified := sess.shutdown()

	r.logger.Info("session killed",
		sessionAttr(found), slog.Int("subscribers_notified", notified))

	return notified, nil
}

// sessionFor looks up sessionID's session, if any.
func (r *Registry) sessionFor(sessionID proto.SessionID) (*session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.sessions[sessionID]
	return sess, ok
}

// AttachSubscriberData validates sessionID (and that its session is TCP-mode,
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
func (r *Registry) AttachSubscriberData(subConn net.Conn, sessionID proto.SessionID, port proto.PortIndex) error {
	sess, ok := r.sessionFor(sessionID)
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
	reqID, ok := sess.addPending(subConn, port)
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
		peerAttr(subConn), sessionAttr(sessionID), slog.Uint64("req", reqID), slog.Any("port", port))

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
// publisher registered with. The sessionID alone can't gate this: every
// subscriber knows it too, and request IDs are guessable (sequential),
// so without the cert check a malicious subscriber could race the real
// publisher to claim another subscriber's pending connection and
// impersonate the shared service.
func (r *Registry) AttachPublisherData(sessionID proto.SessionID, reqID uint64, pubConn *tls.Conn) error {
	sess, ok := r.sessionFor(sessionID)
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

	subConn, port, ok := sess.claimPending(reqID)
	if !ok {
		return fmt.Errorf("unknown or expired request id %d", reqID)
	}

	_ = subConn.SetDeadline(time.Time{})
	_ = pubConn.SetDeadline(time.Time{})
	started := time.Now()

	// Register the stream before splicing and forget it after. A session
	// that shut down between claimPending and here has already been told
	// there is nothing left to tear down, so splicing into it would leave a
	// stream nothing owns - close both legs instead.
	str := &stream{port: port, started: started, counter: &streamio.Counter{}}
	if !sess.addStream(reqID, str) {
		_ = subConn.Close()
		_ = pubConn.Close()
		return errNoSuchSession
	}
	defer sess.removeStream(reqID)

	r.logger.Info(
		"stream paired",
		sessionAttr(sessionID), slog.Uint64("req", reqID),
		slog.Group("subscriber", "addr", subConn.RemoteAddr()),
		slog.Group("publisher", "addr", pubConn.RemoteAddr()),
	)

	// Splice blocks for the whole life of the forwarded connection, so its
	// return values are the only complete record of what the connection
	// carried. str.counter is the same account while it is still running,
	// which is what an operator can actually observe.
	toSub, toPub := streamio.SpliceCounted(subConn, pubConn, str.counter)

	r.logger.Info(
		"stream closed",
		sessionAttr(sessionID), slog.Uint64("req", reqID),
		slog.Int64("bytes_to_subscriber", toSub), slog.Int64("bytes_to_publisher", toPub),
		slog.Duration("duration", time.Since(started).Round(time.Millisecond)),
	)

	return nil
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
