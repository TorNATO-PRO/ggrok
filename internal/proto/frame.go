package proto

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// FrameHeaderSize is the width of a UDP-mode datagram header: a
// SubscriberID naming which subscriber's traffic this is, then a FlowID
// naming which of that subscriber's local clients.
//
// Both legs of the path - listen<->relay and relay<->share - carry this
// same header, even though a subscriber's own leg has no use for the
// SubscriberID field (it has exactly one subscriber: itself). Two bytes
// per datagram buy relay the ability to route without re-framing: it
// reads the header to pick a destination and, on the subscriber-to-
// publisher leg, only overwrites the SubscriberID in place.
const FrameHeaderSize = 4

// frameSubscriberOffset and frameFlowOffset locate the two header fields.
const (
	frameSubscriberOffset = 0
	frameFlowOffset       = 2
)

// BatchHeaderSize is the length prefix in front of each frame packed into
// a QUIC datagram - see MaxBatchSize for why frames are packed at all.
const BatchHeaderSize = 2

// MaxBatchSize is the largest QUIC datagram this tunnel builds, and so the
// budget a batch of frames is packed into.
//
// It has to stay under what quic-go will actually accept, and the cost of
// guessing high is severe: an oversized datagram is rejected whole, losing
// every frame packed into it rather than one. quic-go's own ceiling is
// estimateMaxPayloadSize(InitialPacketSize) = 1280 - 1 - 20 - 16 = 1243
// bytes, and while path-MTU discovery may raise that later, it never
// lowers it - so 1243 is a floor that holds for a connection's whole life.
// 1200 sits below it with room to spare for the DATAGRAM frame's own
// header and an ACK frame sharing the same packet.
const MaxBatchSize = 1200

// MaxFramePayload is the largest datagram payload a frame can carry. It
// falls out of MaxBatchSize: one maximal frame, with its length prefix,
// exactly fills one batch. Sizing it this way means a frame that was
// accepted on read is always packable, so there is no size at which a
// datagram passes one check only to be dropped by the next.
const MaxFramePayload = MaxBatchSize - BatchHeaderSize - FrameHeaderSize

// MaxFrameSize is a maximal frame: its header and the largest payload it
// can carry. With its length prefix it exactly fills one batch.
const MaxFrameSize = FrameHeaderSize + MaxFramePayload

// frameBufferSize is the pooled buffer's full width: the header, the
// largest payload a frame can carry, and one extra byte. That extra byte
// is what makes an oversized datagram detectable - a read that fills the
// payload region completely may have been truncated, so the buffer is
// sized one byte beyond the limit and any read past MaxFramePayload is
// known to be too big rather than merely maximal.
const frameBufferSize = FrameHeaderSize + MaxFramePayload + 1

// frameBufferPool recycles frame buffers so the datagram path doesn't
// allocate per packet. Returning a buffer is safe as soon as the frame has
// been copied into a batch, or as soon as quic.Conn.SendDatagram returns -
// it copies what it's given rather than retaining the caller's slice.
var frameBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, frameBufferSize)
		return &buf
	},
}

// AcquireFrameBuffer takes a frame buffer from the pool, ready for a
// datagram to be read into FramePayloadSpace and framed with FinishFrame.
// Release it with ReleaseFrameBuffer once the frame has been handed on -
// or once it's been decided it won't be.
func AcquireFrameBuffer() *[]byte {
	buf, _ := frameBufferPool.Get().(*[]byte)
	return buf
}

// ReleaseFrameBuffer returns buf to the pool, restoring the full width
// FinishFrame may have trimmed it to.
func ReleaseFrameBuffer(buf *[]byte) {
	*buf = (*buf)[:cap(*buf)]
	frameBufferPool.Put(buf)
}

// FramePayloadSpace is the region of buf a local datagram should be read
// into: everything past the header, so framing it afterwards is a header
// write rather than a copy of the whole payload.
//
// It is one byte longer than MaxFramePayload on purpose. A read returning
// more than MaxFramePayload bytes is one FinishFrame will reject as
// oversized; without that extra byte an oversized datagram would arrive
// truncated and indistinguishable from a maximal one, and get forwarded
// with its tail quietly missing.
func FramePayloadSpace(buf *[]byte) []byte {
	return (*buf)[FrameHeaderSize:]
}

// FinishFrame writes the header in front of the n payload bytes already
// read into FramePayloadSpace(buf), trims buf to the resulting frame, and
// reports whether the datagram was small enough to frame at all.
//
// A false result means the datagram exceeded MaxFramePayload and cannot be
// carried; the caller should drop it and release the buffer. That drop
// costs nothing real, since such a datagram is past what a QUIC datagram
// could hold anyway - it just happens at the point the size is first known
// instead of several copies later.
func FinishFrame(buf *[]byte, sub SubscriberID, flow FlowID, n int) bool {
	if n < 0 || n > MaxFramePayload {
		return false
	}

	frame := (*buf)[:FrameHeaderSize+n]
	binary.BigEndian.PutUint16(frame[frameSubscriberOffset:], uint16(sub))
	binary.BigEndian.PutUint16(frame[frameFlowOffset:], uint16(flow))
	*buf = frame

	return true
}

// EncodeFrame builds a frame in a freshly allocated buffer. The datagram
// path uses AcquireFrameBuffer/FinishFrame instead, which allocates
// nothing; this is for callers that have a payload in hand and no buffer
// to build it in - tests, mostly.
func EncodeFrame(sub SubscriberID, flow FlowID, payload []byte) []byte {
	frame := make([]byte, FrameHeaderSize+len(payload))
	binary.BigEndian.PutUint16(frame[frameSubscriberOffset:], uint16(sub))
	binary.BigEndian.PutUint16(frame[frameFlowOffset:], uint16(flow))
	copy(frame[FrameHeaderSize:], payload)

	return frame
}

// DecodeFrame reads a frame's header and returns it with the payload,
// which aliases frame rather than copying it.
func DecodeFrame(frame []byte) (SubscriberID, FlowID, []byte, error) {
	if len(frame) < FrameHeaderSize {
		return 0, 0, nil, fmt.Errorf("decode frame: short frame (%d bytes)", len(frame))
	}

	sub := SubscriberID(binary.BigEndian.Uint16(frame[frameSubscriberOffset:]))
	flow := FlowID(binary.BigEndian.Uint16(frame[frameFlowOffset:]))

	return sub, flow, frame[FrameHeaderSize:], nil
}

// SetFrameSubscriber overwrites a frame's SubscriberID in place, which is
// how relay stamps a subscriber's datagrams with the identity it
// authenticated rather than the one the peer put there. Doing it in place
// is the point: on the subscriber-to-publisher leg every frame has the
// same destination, so relay restamps each one where it lies and forwards
// the whole datagram untouched otherwise.
func SetFrameSubscriber(frame []byte, sub SubscriberID) error {
	if len(frame) < FrameHeaderSize {
		return fmt.Errorf("set frame subscriber: short frame (%d bytes)", len(frame))
	}

	binary.BigEndian.PutUint16(frame[frameSubscriberOffset:], uint16(sub))

	return nil
}

// Batch packs frames into one QUIC datagram, each behind a length prefix.
//
// Coalescing is what makes this tunnel's throughput a function of bytes
// rather than packets. quic-go puts at most one DATAGRAM frame in a QUIC
// packet, so without batching every forwarded datagram - however small -
// costs its own packet header, its own AEAD seal and its own syscall on
// every hop. Small datagrams are the whole point of a UDP tunnel (game
// traffic, DNS, VoIP), so that per-packet cost, not bandwidth, is what
// saturates the path.
//
// A Batch is not safe for concurrent use; each sending goroutine owns one
// for its lifetime.
type Batch struct {
	buf []byte
}

// NewBatch returns an empty Batch with its full capacity already
// allocated, so packing frames into it never grows or reallocates it.
func NewBatch() *Batch {
	return &Batch{buf: make([]byte, 0, MaxBatchSize)}
}

// Append packs frame into the batch, reporting whether it fit. A false
// result on an empty batch means the frame is unsendable at any time and
// should be dropped; on a non-empty one it just means this batch is full
// and the frame belongs in the next.
func (b *Batch) Append(frame []byte) bool {
	size := len(frame)
	if size < FrameHeaderSize || size > MaxFrameSize {
		return false
	}
	if len(b.buf)+BatchHeaderSize+size > MaxBatchSize {
		return false
	}

	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(size))
	b.buf = append(b.buf, frame...)

	return true
}

// Bytes is the packed datagram, valid until the next Reset.
func (b *Batch) Bytes() []byte { return b.buf }

// Empty reports whether no frame has been packed yet.
func (b *Batch) Empty() bool { return len(b.buf) == 0 }

// Reset empties the batch, keeping its buffer for the next one.
func (b *Batch) Reset() { b.buf = b.buf[:0] }

// FrameReader walks the frames packed into one received datagram.
//
// Every datagram on the wire is a batch, even a batch of one, so every
// receive path iterates rather than decoding a single frame. Frames alias
// the datagram they came from, which is what lets relay restamp them in
// place.
type FrameReader struct {
	rest []byte
}

// NewFrameReader starts reading the frames packed into datagram.
func NewFrameReader(datagram []byte) FrameReader {
	return FrameReader{rest: datagram}
}

// Next returns the next frame, or false once the datagram is exhausted.
//
// A malformed datagram - one whose length prefix runs off the end - stops
// iteration rather than reporting an error, so a peer that sends nonsense
// costs the frames it garbled and nothing more. That matches how the rest
// of the datagram path treats bad input: drop it and keep serving.
func (r *FrameReader) Next() ([]byte, bool) {
	if len(r.rest) < BatchHeaderSize {
		return nil, false
	}

	size := int(binary.BigEndian.Uint16(r.rest))
	if size < FrameHeaderSize || BatchHeaderSize+size > len(r.rest) {
		r.rest = nil
		return nil, false
	}

	frame := r.rest[BatchHeaderSize : BatchHeaderSize+size]
	r.rest = r.rest[BatchHeaderSize+size:]

	return frame, true
}
