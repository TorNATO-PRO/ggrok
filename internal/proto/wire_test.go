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
		{Kind: proto.AttachSubscriber, Token: token, Port: 0xfffe},
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
	wantPort := proto.PortIndex(0x4321)
	if err := proto.WriteRequestData(&buf, want, wantPort); err != nil {
		t.Fatal(err)
	}

	typ, payload, err := proto.ReadControlFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.ControlRequestData {
		t.Errorf("type: got %v, want ControlRequestData", typ)
	}

	got, gotPort, err := proto.ReadRequestData(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %#x, want %#x", got, want)
	}
	if gotPort != wantPort {
		t.Errorf("port: got %#x, want %#x", gotPort, wantPort)
	}
}

// TestReadRequestDataRejectsShortPayload pins the width check that keeps a
// pre-port-range peer's 8-byte payload from being read as a request for
// port 0 - a share would fulfill it against the wrong local service rather
// than refuse it.
func TestReadRequestDataRejectsShortPayload(t *testing.T) {
	t.Parallel()

	if _, _, err := proto.ReadRequestData(make([]byte, 8)); err == nil {
		t.Error("expected error for an 8-byte payload, got nil")
	}
}

func TestHelloRoundTrip(t *testing.T) {
	t.Parallel()

	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	cases := []proto.Hello{
		{Role: proto.RolePublish, Mode: proto.ModeTCP, Ports: 1, Token: token},
		{Role: proto.RoleSubscribe, Mode: proto.ModeUDP, Ports: 1024, Token: token},
	}

	for _, want := range cases {
		var buf bytes.Buffer
		if err := proto.WriteHello(&buf, want); err != nil {
			t.Fatalf("WriteHello(%+v): %v", want, err)
		}

		got, err := proto.ReadHello(&buf)
		if err != nil {
			t.Fatalf("ReadHello: %v", err)
		}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	}
}

// TestHelloRejectsZeroPorts covers both ends of the port count's one
// invariant. A session with no ports forwards nothing, and a zero would
// read as "matches every subscriber that also sent zero" rather than as
// the malformed Hello it is.
func TestHelloRejectsZeroPorts(t *testing.T) {
	t.Parallel()

	hello := proto.Hello{Role: proto.RolePublish, Mode: proto.ModeTCP, Ports: 1}

	var buf bytes.Buffer
	if err := proto.WriteHello(&buf, hello); err != nil {
		t.Fatal(err)
	}

	zeroed := proto.Hello{Role: proto.RolePublish, Mode: proto.ModeTCP}
	if err := proto.WriteHello(&bytes.Buffer{}, zeroed); err == nil {
		t.Error("WriteHello accepted a zero port count, want an error")
	}

	raw := buf.Bytes()
	raw[2], raw[3] = 0, 0 // zero the Ports field
	if _, err := proto.ReadHello(bytes.NewReader(raw)); err == nil {
		t.Error("ReadHello accepted a zero port count, want an error")
	}
}

func TestSubscriberIDRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	want := proto.SubscriberID(0x1234)
	if err := proto.WriteSubscriberID(&buf, want); err != nil {
		t.Fatal(err)
	}

	typ, payload, err := proto.ReadControlFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.ControlSubscriberID {
		t.Errorf("type: got %v, want ControlSubscriberID", typ)
	}

	got, err := proto.ReadSubscriberID(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %#x, want %#x", got, want)
	}
}

func TestReadSubscriberIDRejectsWrongLength(t *testing.T) {
	t.Parallel()

	for _, payload := range [][]byte{nil, {1}, {1, 2, 3}} {
		if _, err := proto.ReadSubscriberID(payload); err == nil {
			t.Errorf("expected error for %d-byte payload, got nil", len(payload))
		}
	}
}

func TestSessionClosedRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	want := proto.ReasonPublisherGone
	if err := proto.WriteSessionClosed(&buf, want); err != nil {
		t.Fatal(err)
	}

	typ, payload, err := proto.ReadControlFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.ControlSessionClosed {
		t.Errorf("type: got %v, want ControlSessionClosed", typ)
	}

	got, err := proto.ReadSessionClosed(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReadSessionClosedRejectsWrongLength(t *testing.T) {
	t.Parallel()

	for _, payload := range [][]byte{nil, {1, 2}} {
		if _, err := proto.ReadSessionClosed(payload); err == nil {
			t.Errorf("expected error for %d-byte payload, got nil", len(payload))
		}
	}
}

// A reason this build doesn't know still has to render as something a
// human can read, since a newer relay may send one.
func TestSessionCloseReasonStringsUnknownValue(t *testing.T) {
	t.Parallel()

	if got := proto.SessionCloseReason(200).String(); got == "" {
		t.Error("unknown reason rendered as empty string")
	}
}

func TestUDPAttachRoundTrip(t *testing.T) {
	t.Parallel()

	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	cases := []proto.UDPAttach{
		{Role: proto.RolePublish, Token: token},
		{Role: proto.RoleSubscribe, Token: token, SubscriberID: 0x2a2a},
	}

	for _, want := range cases {
		var buf bytes.Buffer
		if err := proto.WriteUDPAttach(&buf, want); err != nil {
			t.Fatalf("WriteUDPAttach(%+v): %v", want, err)
		}

		got, err := proto.ReadUDPAttach(&buf)
		if err != nil {
			t.Fatalf("ReadUDPAttach: %v", err)
		}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	}
}

func TestReadUDPAttachRejectsInvalidRole(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := proto.WriteUDPAttach(&buf, proto.UDPAttach{Role: proto.RolePublish}); err != nil {
		t.Fatal(err)
	}

	raw := buf.Bytes()
	raw[0] = 0 // corrupt the Role byte
	if _, err := proto.ReadUDPAttach(bytes.NewReader(raw)); err == nil {
		t.Error("expected error for invalid role, got nil")
	}
}
