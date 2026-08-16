package relay

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/quic-go/quic-go"

	"tornato.dev/ggrok/v2/internal/dgram"
	"tornato.dev/ggrok/v2/internal/proto"
)

// errNotSubscriberCert mirrors errNotPublisherCert for the subscriber
// side: a UDP-mode subscriber's data connection must present the same
// certificate its control connection authenticated with, or a
// differently-certified peer holding the same token and a guessed
// SubscriberID could hijack that subscriber's traffic.
var errNotSubscriberCert = errors.New("data connection certificate does not match this subscriber's control connection")

// udpSenderQueueDepth bounds how many outbound datagrams a udpSender
// buffers for one destination connection. quic-go's own per-connection
// datagram send queue holds only 32 entries, and its SendDatagram call
// blocks the caller once that fills (e.g. while the connection's
// congestion window is closed) - see maxDatagramSendQueueLen in
// quic-go's datagram_queue.go. This just needs to comfortably outlast a
// brief stall on the sending side without growing unbounded; see
// udpSender's doc comment for why that stall must never propagate back
// to a receive loop.
const udpSenderQueueDepth = 256

// udpSender decouples receiving from sending on relay's UDP fan-out
// path. quic-go's ReceiveDatagram queue is only 128 entries deep
// (maxDatagramRcvQueueLen) and silently drops anything received once
// it's full - no error, no backpressure. Calling SendDatagram directly
// from inside a pump's ReceiveDatagram loop means a slow or congested
// destination (blocked on its own 32-entry send queue) stalls that same
// goroutine's next ReceiveDatagram call, which lets its *source*
// connection's receive queue back up and silently drop packets that
// have nothing to do with the slow destination - a self-inflicted,
// platform-independent loss bug. A udpSender gives each destination
// connection its own goroutine and bounded queue, so a congested
// destination only ever costs itself datagrams (dropped once its queue
// is full) instead of stalling whichever pump loop is trying to hand it
// work.
//
// It forwards whole datagrams as handed to it, which is what the
// subscriber-to-publisher direction needs: those arrive already packed
// for the one destination they're bound for. The opposite direction fans
// out to many subscribers and has to repack per destination, so it uses a
// [dgram.Sender] instead.
type udpSender struct {
	conn  *quic.Conn
	queue chan []byte
}

// newUDPSender starts a udpSender for conn. Its goroutine runs until ctx
// is canceled.
func newUDPSender(ctx context.Context, conn *quic.Conn) *udpSender {
	s := &udpSender{conn: conn, queue: make(chan []byte, udpSenderQueueDepth)}
	go s.run(ctx)
	return s
}

func (s *udpSender) run(ctx context.Context) {
	for {
		select {
		case data := <-s.queue:
			_ = s.conn.SendDatagram(data)
		case <-ctx.Done():
			return
		}
	}
}

// enqueue best-effort hands data to the sender goroutine, dropping it
// immediately instead of blocking if the queue is already full - see
// udpSender's doc comment for why the caller must never block here.
func (s *udpSender) enqueue(data []byte) {
	select {
	case s.queue <- data:
	default:
	}
}

// AttachPublisherUDP validates token (and that quicConn's peer
// certificate matches the one the session's publisher registered with -
// see AttachPublisherData's doc comment for why that check exists; the
// same impersonation risk applies here), writes the corresponding ack to
// stream, and - on success - pairs quicConn with the session as its
// relay<->share UDP data-plane connection. It then blocks for the life of
// quicConn, pumping every datagram it receives out to whichever
// subscriber it names; it returns once quicConn errors or ctx is
// canceled, having already cleared the session's reference to it.
func (r *Registry) AttachPublisherUDP(
	ctx context.Context,
	stream io.Writer,
	quicConn *quic.Conn,
	token proto.Token,
) error {
	sess, ok := r.sessionFor(token)
	if !ok {
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return errNoSuchSession
	}
	if sess.mode != proto.ModeUDP {
		_ = proto.WriteAck(stream, proto.AckModeMismatch)
		return errModeMismatch
	}

	cert, err := quicPeerLeafCert(quicConn)
	if err != nil {
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return fmt.Errorf("attach publisher udp: %w", err)
	}
	if !cert.Equal(sess.publisherCert) {
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return errNotPublisherCert
	}

	if err := proto.WriteAck(stream, proto.AckOK); err != nil {
		return fmt.Errorf("ack publisher udp: %w", err)
	}

	senderCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sess.setUDPPublisher(newUDPSender(senderCtx, quicConn))
	defer sess.setUDPPublisher(nil)

	r.logger.InfoContext(ctx, "publisher udp attached", quicPeerAttr(quicConn), sessionAttr(token))
	defer func() {
		r.logger.InfoContext(ctx, "publisher udp detached", quicPeerAttr(quicConn), sessionAttr(token))
	}()

	return pumpPublisherDatagrams(ctx, sess, quicConn)
}

// AttachSubscriberUDP validates token, id (a subscriber id relay already
// assigned over that subscriber's control connection - see
// Registry.Subscribe's ControlSubscriberID frame), and that quicConn's
// peer certificate matches the one that control connection authenticated
// with, writes the corresponding ack to stream, and - on success - pairs
// quicConn with id as its relay<->listen UDP data-plane connection. It
// then blocks for the life of quicConn, pumping every datagram it
// receives to the session's publisher, tagged with id; it returns once
// quicConn errors or ctx is canceled, having already removed the
// session's reference to it.
func (r *Registry) AttachSubscriberUDP(
	ctx context.Context,
	stream io.Writer,
	quicConn *quic.Conn,
	token proto.Token,
	id proto.SubscriberID,
) error {
	sess, ok := r.sessionFor(token)
	if !ok {
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return errNoSuchSession
	}
	if sess.mode != proto.ModeUDP {
		_ = proto.WriteAck(stream, proto.AckModeMismatch)
		return errModeMismatch
	}

	wantCert, err := sess.subscriberCert(id)
	if err != nil {
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return fmt.Errorf("attach subscriber udp: %w", err)
	}

	cert, err := quicPeerLeafCert(quicConn)
	if err != nil {
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return fmt.Errorf("attach subscriber udp: %w", err)
	}
	if !cert.Equal(wantCert) {
		_ = proto.WriteAck(stream, proto.AckNoSuchSession)
		return errNotSubscriberCert
	}

	if err := proto.WriteAck(stream, proto.AckOK); err != nil {
		return fmt.Errorf("ack subscriber udp: %w", err)
	}

	senderCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sess.setUDPSubscriber(id, dgram.NewSender(senderCtx, quicConn))
	defer sess.removeUDPSubscriber(id)

	r.logger.InfoContext(ctx, "subscriber udp attached",
		quicPeerAttr(quicConn), sessionAttr(token), slog.Any("sub", id))
	defer func() {
		r.logger.InfoContext(ctx, "subscriber udp detached", sessionAttr(token), slog.Any("sub", id))
	}()

	return pumpSubscriberDatagrams(ctx, sess, id, quicConn)
}

// pumpPublisherDatagrams reads datagrams off pubConn, decodes the
// (SubscriberID, FlowID) header, and forwards each to the live subscriber
// it names - the publisher-to-subscribers direction of UDP fan-out. A
// datagram naming a subscriber that hasn't attached its own UDP
// connection yet (or has already left) is dropped, same as any other
// malformed or stale frame. Forwarding goes through that subscriber's
// udpSender rather than a direct SendDatagram call - see udpSender's doc
// comment for why this loop must never block on a slow destination.
//
// The datagram is forwarded exactly as it arrived. Both legs of the path
// carry the same header (see proto.FrameHeaderSize), so the frame the
// subscriber needs is already the frame the publisher sent - relay reads
// the header to route it and passes the buffer straight along, without
// allocating or copying the payload.
func pumpPublisherDatagrams(ctx context.Context, sess *session, pubConn *quic.Conn) error {
	for {
		data, err := pubConn.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}

		// One datagram from the publisher can hold frames for any number
		// of different subscribers, so this direction has to take the
		// batch apart and hand each frame to the sender for the subscriber
		// it names. Each of those senders repacks whatever it's given, so
		// traffic arrives coalesced and leaves coalesced - just regrouped
		// by destination along the way.
		frames := proto.NewFrameReader(data)
		for {
			frame, ok := frames.Next()
			if !ok {
				break
			}

			sub, _, _, decodeErr := proto.DecodeFrame(frame)
			if decodeErr != nil {
				continue
			}

			sender, live := sess.udpSubscriber(sub)
			if !live {
				continue
			}

			// The frame aliases data rather than being copied out of it.
			// That's safe to hand to another goroutine: quic-go allocates
			// a fresh slice per received datagram and never reuses it, so
			// data stays valid for as long as the sender holds a frame
			// pointing into it.
			sender.Enqueue(frame)
		}
	}
}

// pumpSubscriberDatagrams reads datagrams off subConn, stamps them with
// id, and forwards each to the session's publisher - the subscriber-to-
// publisher direction of UDP fan-out. A datagram arriving before the
// publisher has attached its own UDP connection is dropped rather than
// buffered, same as any other UDP packet with nowhere to go yet.
// Forwarding goes through the publisher's udpSender rather than a direct
// SendDatagram call - see udpSender's doc comment for why this loop must
// never block on a slow destination.
//
// id is written over whatever the subscriber put in each header rather
// than trusted from it: a peer that stamped another subscriber's id would
// otherwise have its traffic delivered to that subscriber's local clients.
//
// Unlike the publisher-to-subscribers direction, this one needs no
// regrouping - every frame in the datagram is bound for the same place,
// the session's one publisher - so relay restamps each frame where it lies
// and forwards the datagram whole. It crosses relay already coalesced,
// with no allocation and no copy of any payload.
func pumpSubscriberDatagrams(ctx context.Context, sess *session, id proto.SubscriberID, subConn *quic.Conn) error {
	for {
		data, err := subConn.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}

		frames := proto.NewFrameReader(data)
		for {
			frame, ok := frames.Next()
			if !ok {
				break
			}
			_ = proto.SetFrameSubscriber(frame, id) // length already checked by the reader
		}

		sender, ok := sess.udpPublisherSender()
		if !ok {
			continue
		}

		sender.enqueue(data)
	}
}

// quicPeerLeafCert returns conn's verified peer leaf certificate. relay's
// QUIC listener uses the same mTLS config as its TCP listener
// (RequireAndVerifyClientCert), so by the time any post-handshake read
// has succeeded this is always present - but fail closed rather than
// panic if it somehow isn't.
func quicPeerLeafCert(conn *quic.Conn) (*x509.Certificate, error) {
	certs := conn.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no peer certificate")
	}

	return certs[0], nil
}

// quicPeerAttr is peerAttr's counterpart for a QUIC connection.
func quicPeerAttr(conn *quic.Conn) slog.Attr {
	addr := slog.Any("addr", conn.RemoteAddr())

	cert, err := quicPeerLeafCert(conn)
	if err != nil {
		return slog.Group("peer", addr)
	}

	return slog.Group("peer", addr, slog.String("cn", cert.Subject.CommonName))
}
