// Package dgram sends framed datagrams over a QUIC connection, packing
// whatever is already waiting into as few datagrams as it can.
//
// It exists because quic-go puts at most one DATAGRAM frame in a QUIC
// packet: without coalescing, every forwarded datagram costs its own
// packet header, AEAD seal and syscall on every hop, no matter how small
// it is. A UDP tunnel's traffic is mostly small datagrams, so that
// per-packet cost is what bounds throughput - see internal/proto.Batch.
package dgram

import (
	"context"

	"github.com/quic-go/quic-go"

	"tornato.dev/ggrok/v2/internal/proto"
)

// QueueDepth bounds how many frames a Sender holds for one destination
// connection.
//
// quic-go's own per-connection datagram send queue holds only 32 entries,
// and SendDatagram blocks the caller once that fills - e.g. while the
// connection's congestion window is closed. This queue is what keeps that
// stall away from whichever loop is producing frames: a congested
// destination costs itself datagrams, dropped once its queue is full,
// instead of stalling a reader that serves other destinations too.
const QueueDepth = 256

// queued is one frame waiting to be packed. pooled is the buffer to
// return once the frame has been copied into a batch, and is nil when the
// frame aliases memory the Sender doesn't own.
type queued struct {
	frame  []byte
	pooled *[]byte
}

// release returns a queued frame's buffer to the pool, if it had one.
func (q queued) release() {
	if q.pooled != nil {
		proto.ReleaseFrameBuffer(q.pooled)
	}
}

// Sender owns one QUIC connection's outbound datagram path: callers hand
// it frames, and its goroutine packs them into datagrams and sends them.
type Sender struct {
	conn  *quic.Conn
	queue chan queued
}

// NewSender starts a Sender for conn. Its goroutine runs until ctx is
// canceled.
func NewSender(ctx context.Context, conn *quic.Conn) *Sender {
	s := &Sender{conn: conn, queue: make(chan queued, QueueDepth)}
	go s.run(ctx)

	return s
}

// Enqueue offers a frame that aliases memory the caller owns, dropping it
// if the queue is full. The frame is copied into a batch before the next
// receive on the connection it came from, so it only has to stay valid
// until then.
func (s *Sender) Enqueue(frame []byte) {
	s.offer(queued{frame: frame})
}

// EnqueuePooled offers a frame in a pooled buffer, taking ownership of
// that buffer: it goes back to the pool once the frame is packed, or
// immediately if the queue is full and the frame is dropped.
func (s *Sender) EnqueuePooled(buf *[]byte) {
	q := queued{frame: *buf, pooled: buf}
	if !s.offer(q) {
		q.release()
	}
}

// Close tears down the underlying connection.
func (s *Sender) Close() {
	_ = s.conn.CloseWithError(0, "")
}

// offer hands q to the sender goroutine, reporting false rather than
// blocking if the queue is already full - see QueueDepth for why a
// producer must never block here.
func (s *Sender) offer(q queued) bool {
	select {
	case s.queue <- q:
		return true
	default:
		return false
	}
}

// run packs queued frames into datagrams and sends them until ctx ends.
//
// Nothing is ever waited for. A frame arriving to an idle sender is packed
// alone and goes out immediately, so coalescing costs no latency; it only
// absorbs frames that had already piled up behind a send. The busier the
// connection, the more each datagram carries - which is exactly when
// per-packet cost is what's hurting.
func (s *Sender) run(ctx context.Context) {
	batch := proto.NewBatch()

	// A frame that didn't fit the batch being built starts the next one,
	// so it has to survive into the following iteration.
	var carry queued
	var carried bool

	for {
		first := carry
		if carried {
			carried = false
		} else {
			select {
			case first = <-s.queue:
			case <-ctx.Done():
				return
			}
		}

		batch.Reset()
		fits := batch.Append(first.frame)
		first.release()
		if !fits {
			continue // unsendable at any size; dropping is all that's left
		}

	pack:
		for {
			select {
			case next := <-s.queue:
				if !batch.Append(next.frame) {
					carry, carried = next, true
					break pack
				}
				next.release()
			default:
				break pack
			}
		}

		_ = s.conn.SendDatagram(batch.Bytes())
	}
}
