// Package relay is the rendezvous point between share (publisher) and
// listen (subscriber) connections: it pairs them by token and mirrors
// QUIC-level events (new stream, datagram) between them. It never
// terminates TCP or UDP itself - see the "Fan-out design" section of
// docs/plans/tcp-udp-tunnel.md for why UDP mode is the one place that
// costs relay its "dumb pipe" purity (it has to read a small per-datagram
// header to route replies to the right subscriber).
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quic-go/quic-go"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/streamio"
)

// errPublisherExists and errNoSuchSession are the only two ways Register
// or Bridge deliberately reject a peer; Bridge also distinguishes a mode
// mismatch. They map 1:1 to proto.AckStatus values.
var (
	errPublisherExists = errors.New("token already has an active publisher")
	errNoSuchSession   = errors.New("no active session for this token")
	errModeMismatch    = errors.New("mode does not match this session's publisher")
)

// Registry holds every currently-active session, keyed by token.
type Registry struct {
	mu       sync.Mutex
	sessions map[proto.Token]*session
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[proto.Token]*session)}
}

// Register adds conn as token's publisher and writes the corresponding ack
// to stream. On success it returns an unregister func the caller must
// invoke (e.g. via defer) once conn is done, so a later publish under the
// same token can succeed; the returned error is nil. On failure the
// returned func is nil and the error describes why. Callers must not
// actively close conn in that case - see Bridge's doc comment for why;
// the same reasoning applies here.
func (r *Registry) Register(stream io.Writer, token proto.Token, mode proto.Mode, conn *quic.Conn) (func(), error) {
	r.mu.Lock()
	if _, exists := r.sessions[token]; exists {
		r.mu.Unlock()
		_ = proto.WriteAck(stream, proto.AckPublisherExists)
		return nil, errPublisherExists
	}

	sess := newSession(mode, conn)
	r.sessions[token] = sess
	r.mu.Unlock()

	if err := proto.WriteAck(stream, proto.AckOK); err != nil {
		r.mu.Lock()
		delete(r.sessions, token)
		r.mu.Unlock()
		return nil, fmt.Errorf("ack publisher: %w", err)
	}

	return func() {
		r.mu.Lock()
		delete(r.sessions, token)
		r.mu.Unlock()
		sess.stopUDP()
	}, nil
}

// Bridge attaches subscriberConn to token's session and writes the
// corresponding ack to stream. On success it then runs the fan-out loop -
// mirroring TCP streams or forwarding UDP datagrams, per mode - until ctx
// is done or subscriberConn errors, and returns that terminal error. On
// rejection (no such session, a mode mismatch, or the ack write itself
// failing) the rejection ack has already been written and Bridge returns
// immediately. Callers must not actively close subscriberConn on error:
// CloseWithError tears a connection down immediately regardless of
// whether a prior stream Write has actually reached the peer yet, so
// closing right after writing a rejection ack can race the peer's read of
// that very ack. Leaving the connection for quic-go's own MaxIdleTimeout
// to reap sidesteps the race entirely.
func (r *Registry) Bridge(
	ctx context.Context,
	stream io.Writer,
	token proto.Token,
	mode proto.Mode,
	subscriberConn *quic.Conn,
) error {
	r.mu.Lock()
	sess, ok := r.sessions[token]
	r.mu.Unlock()

	switch {
	case !ok:
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return errNoSuchSession
	case sess.mode != mode:
		_ = proto.WriteAck(stream, proto.AckModeMismatch)
		return errModeMismatch
	}

	if err := proto.WriteAck(stream, proto.AckOK); err != nil {
		return fmt.Errorf("ack subscriber: %w", err)
	}

	subID, release := sess.addSubscriber(subscriberConn)
	defer release()

	switch mode {
	case proto.ModeTCP:
		return bridgeTCP(ctx, subscriberConn, sess.publisher)
	case proto.ModeUDP:
		return sess.bridgeUDP(ctx, subID, subscriberConn)
	default:
		return fmt.Errorf("relay: unsupported mode %v", mode)
	}
}

// session is one active publisher and its currently-attached subscribers.
type session struct {
	mode      proto.Mode
	publisher *quic.Conn

	mu          sync.Mutex
	subscribers map[proto.SubscriberID]*quic.Conn
	nextSubID   proto.SubscriberID

	// udpCancel stops the session's publisher-side UDP demux goroutine
	// (see udp.go); non-nil exactly while that goroutine is running.
	udpCancel context.CancelFunc
}

func newSession(mode proto.Mode, publisher *quic.Conn) *session {
	return &session{mode: mode, publisher: publisher, subscribers: make(map[proto.SubscriberID]*quic.Conn)}
}

// addSubscriber registers conn under a freshly allocated SubscriberID,
// starting the session's publisher-side UDP demux goroutine if this is the
// first subscriber in UDP mode. The returned release func removes the
// subscriber - and stops that goroutine if it was the last one - and must
// be called once the subscriber is done.
func (s *session) addSubscriber(conn *quic.Conn) (proto.SubscriberID, func()) {
	s.mu.Lock()
	id := s.nextSubID
	s.nextSubID++
	s.subscribers[id] = conn

	if s.mode == proto.ModeUDP && s.udpCancel == nil {
		udpCtx, cancel := context.WithCancel(context.Background())
		s.udpCancel = cancel
		go s.pumpPublisherDatagrams(udpCtx)
	}
	s.mu.Unlock()

	return id, func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		if len(s.subscribers) == 0 {
			s.stopUDPLocked()
		}
		s.mu.Unlock()
	}
}

// stopUDP stops the session's publisher-side UDP demux goroutine, if one
// is running.
func (s *session) stopUDP() {
	s.mu.Lock()
	s.stopUDPLocked()
	s.mu.Unlock()
}

// stopUDPLocked is stopUDP's body; s.mu must already be held.
func (s *session) stopUDPLocked() {
	if s.udpCancel != nil {
		s.udpCancel()
		s.udpCancel = nil
	}
}

// bridgeTCP mirrors every stream subscriberConn opens onto a freshly
// opened stream on publisherConn and splices bytes between them. It runs
// until ctx is done or subscriberConn errors.
func bridgeTCP(ctx context.Context, subscriberConn, publisherConn *quic.Conn) error {
	for {
		subStream, err := subscriberConn.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("accept subscriber stream: %w", err)
		}

		pubStream, err := publisherConn.OpenStreamSync(ctx)
		if err != nil {
			subStream.CancelWrite(0)
			subStream.CancelRead(0)
			continue // publisher likely just disconnected; the next AcceptStream will surface that
		}

		go streamio.Splice(subStream, pubStream)
	}
}
