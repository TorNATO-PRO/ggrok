package proto_test

import (
	"bytes"
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
)

// TestBatchRoundTrip checks that frames packed into one datagram come back
// out in order and unchanged - the property every receive path relies on.
func TestBatchRoundTrip(t *testing.T) {
	t.Parallel()

	want := [][]byte{
		proto.EncodeFrame(1, 10, []byte("first")),
		proto.EncodeFrame(2, 20, []byte("")),
		proto.EncodeFrame(3, 30, bytes.Repeat([]byte{0xab}, 300)),
	}

	batch := proto.NewBatch()
	for i, frame := range want {
		if !batch.Append(frame) {
			t.Fatalf("Append(%d) rejected a frame that should fit", i)
		}
	}

	var got [][]byte
	frames := proto.NewFrameReader(batch.Bytes())
	for {
		frame, ok := frames.Next()
		if !ok {
			break
		}
		got = append(got, frame)
	}

	if len(got) != len(want) {
		t.Fatalf("read back %d frames, packed %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("frame %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestBatchFillsToCapacity pins the two sizing invariants the sender's
// packing loop depends on: a maximal frame always fits an empty batch (so
// a frame accepted on read is never unsendable), and a batch never grows
// past what MaxBatchSize budgets for a QUIC datagram.
func TestBatchFillsToCapacity(t *testing.T) {
	t.Parallel()

	batch := proto.NewBatch()
	maximal := proto.EncodeFrame(1, 1, make([]byte, proto.MaxFramePayload))

	if !batch.Append(maximal) {
		t.Fatal("a maximal frame did not fit an empty batch")
	}
	if len(batch.Bytes()) != proto.MaxBatchSize {
		t.Errorf("a maximal frame filled %d bytes, want exactly MaxBatchSize (%d)",
			len(batch.Bytes()), proto.MaxBatchSize)
	}
	if batch.Append(proto.EncodeFrame(1, 1, nil)) {
		t.Error("Append accepted a frame into an already-full batch")
	}

	batch.Reset()
	if !batch.Empty() {
		t.Error("Reset left the batch non-empty")
	}

	// Pack small frames until it refuses, then check it stayed in budget.
	small := proto.EncodeFrame(1, 1, make([]byte, 64))
	for batch.Append(small) {
		// Filling it up is the whole point; the loop ends when it refuses.
	}
	if len(batch.Bytes()) > proto.MaxBatchSize {
		t.Errorf("packed batch is %d bytes, over MaxBatchSize (%d)",
			len(batch.Bytes()), proto.MaxBatchSize)
	}
}

// TestBatchRejectsRunts covers the guard that keeps a frame too short to
// carry a header out of a batch, since every reader decodes what it gets
// back assuming a header is there.
func TestBatchRejectsRunts(t *testing.T) {
	t.Parallel()

	batch := proto.NewBatch()
	for size := range proto.FrameHeaderSize {
		if batch.Append(make([]byte, size)) {
			t.Errorf("Append accepted a %d-byte frame", size)
		}
	}
}

// TestFrameReaderStopsOnMalformed checks that a datagram whose length
// prefix doesn't match its contents costs only the frames it garbled: the
// reader stops rather than reading past the end or spinning.
func TestFrameReaderStopsOnMalformed(t *testing.T) {
	t.Parallel()

	good := proto.EncodeFrame(1, 1, []byte("intact"))

	batch := proto.NewBatch()
	if !batch.Append(good) {
		t.Fatal("Append rejected a normal frame")
	}

	// A second entry claiming far more bytes than actually follow.
	truncated := append(bytes.Clone(batch.Bytes()), 0xff, 0xff, 0x00, 0x00, 0x00, 0x00)

	frames := proto.NewFrameReader(truncated)

	first, ok := frames.Next()
	if !ok {
		t.Fatal("reader rejected the intact frame ahead of the bad one")
	}
	if !bytes.Equal(first, good) {
		t.Errorf("first frame = %v, want %v", first, good)
	}

	if _, ok := frames.Next(); ok {
		t.Error("reader returned a frame from a length prefix running off the end")
	}
	if _, ok := frames.Next(); ok {
		t.Error("reader restarted after stopping on a malformed frame")
	}
}

// TestFrameReaderOnEmpty checks the degenerate inputs a peer can always
// produce: nothing at all, and a stub too short to hold a length prefix.
func TestFrameReaderOnEmpty(t *testing.T) {
	t.Parallel()

	for _, datagram := range [][]byte{nil, {}, {0x00}} {
		frames := proto.NewFrameReader(datagram)
		if _, ok := frames.Next(); ok {
			t.Errorf("reader returned a frame from %d bytes", len(datagram))
		}
	}
}
