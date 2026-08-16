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

// TestBatchAppendPackedMerges checks the property relay's fan-in leg rests
// on: two datagrams, each already a packed run of frames, concatenate into
// one batch that reads back as every frame of the first followed by every
// frame of the second.
func TestBatchAppendPackedMerges(t *testing.T) {
	t.Parallel()

	first := proto.NewBatch()
	firstFrames := [][]byte{
		proto.EncodeFrame(1, 10, []byte("sub one, flow ten")),
		proto.EncodeFrame(1, 11, []byte("sub one, flow eleven")),
	}
	for _, frame := range firstFrames {
		if !first.Append(frame) {
			t.Fatal("Append rejected a frame that should fit")
		}
	}

	second := proto.NewBatch()
	secondFrames := [][]byte{
		proto.EncodeFrame(2, 20, []byte("sub two")),
		proto.EncodeFrame(3, 30, bytes.Repeat([]byte{0xcd}, 200)),
	}
	for _, frame := range secondFrames {
		if !second.Append(frame) {
			t.Fatal("Append rejected a frame that should fit")
		}
	}

	merged := proto.NewBatch()
	if !merged.AppendPacked(first.Bytes()) {
		t.Fatal("AppendPacked rejected the first packed run")
	}
	if !merged.AppendPacked(second.Bytes()) {
		t.Fatal("AppendPacked rejected the second packed run")
	}

	want := append(append([][]byte{}, firstFrames...), secondFrames...)

	var got [][]byte
	frames := proto.NewFrameReader(merged.Bytes())
	for {
		frame, ok := frames.Next()
		if !ok {
			break
		}
		got = append(got, frame)
	}

	if len(got) != len(want) {
		t.Fatalf("merged batch read back %d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("merged frame %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestBatchAppendPackedStaysInBudget checks that merging respects the same
// MaxBatchSize ceiling packing does. Overshooting it is the one failure
// mode that costs more than the frame that caused it: quic-go rejects an
// oversized datagram whole, so every merged-in frame would go down with it.
func TestBatchAppendPackedStaysInBudget(t *testing.T) {
	t.Parallel()

	full := proto.NewBatch()
	if !full.Append(proto.EncodeFrame(1, 1, make([]byte, proto.MaxFramePayload))) {
		t.Fatal("a maximal frame did not fit an empty batch")
	}

	// A maximal frame already fills the budget exactly, so nothing can be
	// merged onto it - and the batch must be left untouched by the refusal.
	merged := proto.NewBatch()
	if !merged.AppendPacked(full.Bytes()) {
		t.Fatal("AppendPacked rejected a run that exactly fills the budget")
	}

	small := proto.NewBatch()
	if !small.Append(proto.EncodeFrame(2, 2, []byte("tiny"))) {
		t.Fatal("Append rejected a small frame")
	}
	if merged.AppendPacked(small.Bytes()) {
		t.Error("AppendPacked overflowed a batch that was already full")
	}
	if len(merged.Bytes()) != proto.MaxBatchSize {
		t.Errorf("refused merge left the batch at %d bytes, want MaxBatchSize (%d)",
			len(merged.Bytes()), proto.MaxBatchSize)
	}
}

// TestBatchAppendPackedRejectsRunts covers the inputs that can't be a
// packed run of frames at all: too short to hold even one length prefix
// and header.
func TestBatchAppendPackedRejectsRunts(t *testing.T) {
	t.Parallel()

	batch := proto.NewBatch()
	for size := range proto.BatchHeaderSize + proto.FrameHeaderSize {
		if batch.AppendPacked(make([]byte, size)) {
			t.Errorf("AppendPacked accepted a %d-byte run", size)
		}
	}
	if !batch.Empty() {
		t.Error("a refused AppendPacked left bytes in the batch")
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

// TestFrameReaderConsumed checks the valid-prefix length a forwarder uses
// to strip a malformed tail before passing a datagram on. Getting this
// wrong is what would let garbage survive into a merged batch and swallow
// every frame behind it - see [proto.Batch.AppendPacked].
func TestFrameReaderConsumed(t *testing.T) {
	t.Parallel()

	batch := proto.NewBatch()
	for _, frame := range [][]byte{
		proto.EncodeFrame(1, 1, []byte("first")),
		proto.EncodeFrame(2, 2, []byte("second")),
	} {
		if !batch.Append(frame) {
			t.Fatal("Append rejected a frame that should fit")
		}
	}
	intact := bytes.Clone(batch.Bytes())

	for _, tc := range []struct {
		name     string
		datagram []byte
		want     int
	}{
		{"clean", intact, len(intact)},
		{"empty", nil, 0},
		{"runt", []byte{0x00}, 0},
		// A length prefix claiming more bytes than actually follow: the
		// two good frames count, the garbage does not.
		{"malformed tail", append(bytes.Clone(intact), 0xff, 0xff, 0x01), len(intact)},
		// A tail too short to even hold a length prefix.
		{"stray byte", append(bytes.Clone(intact), 0x00), len(intact)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := consumedAfterWalk(tc.datagram); got != tc.want {
				t.Errorf("Consumed() = %d, want %d", got, tc.want)
			}

			// The prefix it reports must itself be a batch: that is the
			// whole reason a forwarder trusts it enough to merge it.
			if tc.want > 0 && !proto.NewBatch().AppendPacked(tc.datagram[:tc.want]) {
				t.Error("AppendPacked rejected the prefix Consumed reported as valid")
			}
		})
	}
}

// consumedAfterWalk reads datagram to exhaustion and reports the valid
// prefix length the reader ended up with.
func consumedAfterWalk(datagram []byte) int {
	frames := proto.NewFrameReader(datagram)
	for {
		if _, ok := frames.Next(); !ok {
			return frames.Consumed()
		}
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
