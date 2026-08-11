package proto_test

import (
	"bytes"
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
)

// oversizedControlPayload is safely larger than proto's internal
// maxControlPayload bound without depending on that unexported constant
// from this black-box test package.
const oversizedControlPayload = 1 << 20

func TestConnKindRoundTrip(t *testing.T) {
	t.Parallel()

	for _, kind := range []proto.ConnKind{proto.ConnControl, proto.ConnData} {
		var buf bytes.Buffer
		if err := proto.WriteConnKind(&buf, kind); err != nil {
			t.Fatalf("WriteConnKind(%v): %v", kind, err)
		}

		got, err := proto.ReadConnKind(&buf)
		if err != nil {
			t.Fatalf("ReadConnKind: %v", err)
		}
		if got != kind {
			t.Errorf("got %v, want %v", got, kind)
		}
	}
}

func TestReadConnKindRejectsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := proto.ReadConnKind(bytes.NewReader([]byte{0})); err == nil {
		t.Error("expected error for kind 0, got nil")
	}
}

func TestAttachRoundTrip(t *testing.T) {
	t.Parallel()

	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	cases := []proto.Attach{
		{Kind: proto.AttachSubscriber, Token: token},
		{Kind: proto.AttachPublisher, Token: token, RequestID: 0xdeadbeef},
	}

	for _, want := range cases {
		var buf bytes.Buffer
		if err := proto.WriteAttach(&buf, want); err != nil {
			t.Fatalf("WriteAttach(%+v): %v", want, err)
		}

		got, err := proto.ReadAttach(&buf)
		if err != nil {
			t.Fatalf("ReadAttach: %v", err)
		}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	}
}

func TestReadAttachRejectsInvalidKind(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := proto.WriteAttach(&buf, proto.Attach{Kind: proto.AttachSubscriber}); err != nil {
		t.Fatal(err)
	}

	raw := buf.Bytes()
	raw[0] = 0 // corrupt the Kind byte
	if _, err := proto.ReadAttach(bytes.NewReader(raw)); err == nil {
		t.Error("expected error for invalid kind, got nil")
	}
}

func TestControlFrameRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		typ     proto.ControlType
		payload []byte
	}{
		{proto.ControlPing, nil},
		{proto.ControlPong, []byte{}},
		{proto.ControlRequestData, []byte{0, 0, 0, 0, 0, 0, 0, 42}},
	}

	for _, c := range cases {
		var buf bytes.Buffer
		if err := proto.WriteControlFrame(&buf, c.typ, c.payload); err != nil {
			t.Fatalf("WriteControlFrame(%v): %v", c.typ, err)
		}

		gotTyp, gotPayload, err := proto.ReadControlFrame(&buf)
		if err != nil {
			t.Fatalf("ReadControlFrame: %v", err)
		}
		if gotTyp != c.typ {
			t.Errorf("type: got %v, want %v", gotTyp, c.typ)
		}
		if !bytes.Equal(gotPayload, c.payload) {
			t.Errorf("payload: got %v, want %v", gotPayload, c.payload)
		}
	}
}

func TestWriteControlFrameRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	huge := make([]byte, oversizedControlPayload)
	if err := proto.WriteControlFrame(&buf, proto.ControlPing, huge); err == nil {
		t.Error("expected error for oversized payload, got nil")
	}
}

func TestReadControlFrameRejectsOversizedLengthPrefix(t *testing.T) {
	t.Parallel()

	// Header claiming a payload far larger than proto's internal bound,
	// with no actual payload bytes following - ReadControlFrame must
	// reject based on the length prefix alone, not hang trying to read it.
	header := []byte{byte(proto.ControlPing), 0x7f, 0xff, 0xff, 0xff}
	if _, _, err := proto.ReadControlFrame(bytes.NewReader(header)); err == nil {
		t.Error("expected error for oversized length prefix, got nil")
	}
}

func TestRequestDataRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	want := uint64(0x0123456789abcdef)
	if err := proto.WriteRequestData(&buf, want); err != nil {
		t.Fatal(err)
	}

	typ, payload, err := proto.ReadControlFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.ControlRequestData {
		t.Errorf("type: got %v, want ControlRequestData", typ)
	}

	got, err := proto.ReadRequestData(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %#x, want %#x", got, want)
	}
}

func TestUDPSessionRoundTrip(t *testing.T) {
	t.Parallel()

	want, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if writeErr := proto.WriteUDPSession(&buf, want); writeErr != nil {
		t.Fatal(writeErr)
	}

	typ, payload, err := proto.ReadControlFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.ControlUDPSession {
		t.Errorf("type: got %v, want ControlUDPSession", typ)
	}

	got, err := proto.ReadUDPSession(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestNewRoutingIDIsRandom(t *testing.T) {
	t.Parallel()

	a, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two calls to NewRoutingID produced the same id")
	}
}
