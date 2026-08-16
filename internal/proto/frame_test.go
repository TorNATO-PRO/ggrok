package proto_test

import (
	"bytes"
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
)

// TestFrameRoundTrip checks the straightforward encode/decode path both
// legs of the UDP data plane share.
func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		sub     proto.SubscriberID
		flow    proto.FlowID
		payload []byte
	}{
		{"empty payload", 1, 2, []byte{}},
		{"typical", 7, 9, []byte("hello tunnel")},
		{"zero ids", 0, 0, []byte{0xff, 0x00, 0xff}},
		{"max ids", 0xffff, 0xffff, []byte("edges")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			sub, flow, payload, err := proto.DecodeFrame(proto.EncodeFrame(c.sub, c.flow, c.payload))
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}
			if sub != c.sub {
				t.Errorf("sub = %d, want %d", sub, c.sub)
			}
			if flow != c.flow {
				t.Errorf("flow = %d, want %d", flow, c.flow)
			}
			if !bytes.Equal(payload, c.payload) {
				t.Errorf("payload = %q, want %q", payload, c.payload)
			}
		})
	}
}

// TestFinishFrameMatchesEncodeFrame pins the pooled-buffer path to the
// allocating one: a datagram read into FramePayloadSpace and framed by
// FinishFrame must be byte-identical to what EncodeFrame would have built,
// since the two are used interchangeably across the wire.
func TestFinishFrameMatchesEncodeFrame(t *testing.T) {
	t.Parallel()

	const (
		sub  = proto.SubscriberID(0x1234)
		flow = proto.FlowID(0x5678)
	)
	payload := []byte("datagram body")

	buf := proto.AcquireFrameBuffer()
	defer proto.ReleaseFrameBuffer(buf)

	n := copy(proto.FramePayloadSpace(buf), payload)
	if !proto.FinishFrame(buf, sub, flow, n) {
		t.Fatal("FinishFrame rejected a payload well under the limit")
	}

	if want := proto.EncodeFrame(sub, flow, payload); !bytes.Equal(*buf, want) {
		t.Errorf("FinishFrame produced %v, EncodeFrame produced %v", *buf, want)
	}
}

// TestFinishFrameRejectsOversized covers the case the extra byte in a
// frame buffer exists for: a datagram larger than MaxFramePayload fills
// the payload space past the limit and must be reported as unframeable,
// rather than being forwarded silently truncated.
func TestFinishFrameRejectsOversized(t *testing.T) {
	t.Parallel()

	buf := proto.AcquireFrameBuffer()
	defer proto.ReleaseFrameBuffer(buf)

	space := proto.FramePayloadSpace(buf)
	if len(space) <= proto.MaxFramePayload {
		t.Fatalf("payload space is %d bytes, needs to exceed MaxFramePayload (%d) "+
			"for an oversized datagram to be distinguishable from a maximal one",
			len(space), proto.MaxFramePayload)
	}

	if proto.FinishFrame(buf, 1, 1, proto.MaxFramePayload) != true {
		t.Error("FinishFrame rejected a payload of exactly MaxFramePayload")
	}
	if proto.FinishFrame(buf, 1, 1, proto.MaxFramePayload+1) {
		t.Error("FinishFrame accepted a payload past MaxFramePayload")
	}
}

// TestSetFrameSubscriber checks relay's in-place restamp: only the
// SubscriberID changes, and the flow and payload survive untouched.
func TestSetFrameSubscriber(t *testing.T) {
	t.Parallel()

	payload := []byte("payload must survive")
	frame := proto.EncodeFrame(1, 42, payload)

	if err := proto.SetFrameSubscriber(frame, 0xbeef); err != nil {
		t.Fatalf("SetFrameSubscriber: %v", err)
	}

	sub, flow, got, err := proto.DecodeFrame(frame)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if sub != 0xbeef {
		t.Errorf("sub = %#x, want 0xbeef", sub)
	}
	if flow != 42 {
		t.Errorf("flow = %d, want 42", flow)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

// TestShortFramesRejected covers the truncated-frame guard on both
// header-reading entry points, since a misbehaving peer can send anything.
func TestShortFramesRejected(t *testing.T) {
	t.Parallel()

	for size := range proto.FrameHeaderSize {
		frame := make([]byte, size)

		if _, _, _, err := proto.DecodeFrame(frame); err == nil {
			t.Errorf("DecodeFrame accepted a %d-byte frame", size)
		}
		if err := proto.SetFrameSubscriber(frame, 1); err == nil {
			t.Errorf("SetFrameSubscriber accepted a %d-byte frame", size)
		}
	}
}

// TestReleaseFrameBufferRestoresFullWidth pins the pool's contract:
// FinishFrame trims a buffer to its frame, so releasing it has to restore
// the full width or every recycled buffer would be shorter than the last
// until the path could no longer carry a full-size datagram.
func TestReleaseFrameBufferRestoresFullWidth(t *testing.T) {
	t.Parallel()

	buf := proto.AcquireFrameBuffer()
	full := len(*buf)

	if !proto.FinishFrame(buf, 1, 1, 1) {
		t.Fatal("FinishFrame rejected a one-byte payload")
	}
	if len(*buf) == full {
		t.Fatal("FinishFrame did not trim the buffer, so this test proves nothing")
	}

	proto.ReleaseFrameBuffer(buf)

	if len(*buf) != full {
		t.Errorf("released buffer is %d bytes, want %d", len(*buf), full)
	}
}
