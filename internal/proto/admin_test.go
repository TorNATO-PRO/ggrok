package proto_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
)

func TestAdminFrameRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		typ     proto.AdminType
		payload any
	}{
		{name: "hello", typ: proto.AdminHello, payload: proto.AdminHelloPayload{Version: proto.AdminVersion}},
		{name: "ack", typ: proto.AdminAck, payload: proto.AdminAckPayload{OK: true, Version: 1}},
		{name: "refusal", typ: proto.AdminAck, payload: proto.AdminAckPayload{Err: "nope", Version: 1}},
		{name: "empty payload", typ: proto.AdminList, payload: nil},
		{name: "kick", typ: proto.AdminKick, payload: proto.AdminKickPayload{Serial: "deadbeef"}},
		{
			name:    "result",
			typ:     proto.AdminResult,
			payload: proto.AdminResultPayload{OK: true, Detail: "done", Affected: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			if err := proto.WriteAdminFrame(&buf, tt.typ, tt.payload); err != nil {
				t.Fatalf("write: %v", err)
			}

			typ, body, err := proto.ReadAdminFrame(&buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if typ != tt.typ {
				t.Fatalf("type = %s, want %s", typ, tt.typ)
			}
			if buf.Len() != 0 {
				t.Fatalf("%d bytes left unread after one frame", buf.Len())
			}
			assertBodyShape(t, tt.payload, body)
		})
	}
}

// assertBodyShape checks that a nil payload round-trips to an empty body and
// a non-nil one does not, so "the frame carried nothing" and "the frame
// carried something we failed to encode" stay distinguishable.
func assertBodyShape(t *testing.T, payload any, body []byte) {
	t.Helper()

	if payload == nil {
		if len(body) != 0 {
			t.Fatalf("nil payload produced %d body bytes", len(body))
		}

		return
	}
	if len(body) == 0 {
		t.Fatal("non-nil payload produced an empty body")
	}
}

// TestAdminSnapshotRoundTrip covers the one payload with nested structure and
// timestamps, since those are what a hand-rolled encoding would get wrong.
func TestAdminSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Millisecond)
	want := proto.Snapshot{
		Now: now,
		Sessions: []proto.SessionSummary{{
			Tag:         "a1b2c3d4e5f6",
			Mode:        "tcp",
			Ports:       4,
			Since:       now.Add(-time.Hour),
			Publisher:   proto.PeerSummary{CN: "laptop", Serial: "ff00", Addr: "10.0.0.1:1", Since: now},
			Subscribers: []proto.PeerSummary{{CN: "phone", Serial: "ff01", Addr: "10.0.0.2:2", Since: now}},
			Streams: []proto.StreamSummary{{
				ReqID: 9, Port: 2, Started: now, BytesToSub: 1 << 40, BytesToPub: 7,
			}},
			Pending: []proto.PendingSummary{{ReqID: 10, Port: 3, Since: now, Address: "10.0.0.3:3"}},
		}},
	}

	var buf bytes.Buffer
	if err := proto.WriteAdminFrame(&buf, proto.AdminSnapshot, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	typ, body, err := proto.ReadAdminFrame(&buf)
	if err != nil || typ != proto.AdminSnapshot {
		t.Fatalf("read = %s, %v", typ, err)
	}

	var got proto.Snapshot
	if err := proto.DecodeAdminPayload(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !got.Now.Equal(want.Now) || len(got.Sessions) != 1 {
		t.Fatalf("snapshot header = %v, %d sessions", got.Now, len(got.Sessions))
	}
	gotSess, wantSess := got.Sessions[0], want.Sessions[0]
	if gotSess.Tag != wantSess.Tag || gotSess.Ports != wantSess.Ports || gotSess.Mode != wantSess.Mode {
		t.Fatalf("session = %+v", gotSess)
	}
	if gotSess.Publisher != wantSess.Publisher {
		t.Fatalf("publisher = %+v, want %+v", gotSess.Publisher, wantSess.Publisher)
	}
	if len(gotSess.Subscribers) != 1 || gotSess.Subscribers[0] != wantSess.Subscribers[0] {
		t.Fatalf("subscribers = %+v", gotSess.Subscribers)
	}
	if len(gotSess.Streams) != 1 || gotSess.Streams[0] != wantSess.Streams[0] {
		t.Fatalf("streams = %+v, want %+v", gotSess.Streams, wantSess.Streams)
	}
	if len(gotSess.Pending) != 1 || gotSess.Pending[0] != wantSess.Pending[0] {
		t.Fatalf("pending = %+v", gotSess.Pending)
	}
}

// TestWriteAdminHelloCarriesConnKind pins the discriminator to the frame. A
// bare AdminHello has type byte 1, which is also ConnControl, so omitting the
// kind is not a loud failure - relay dispatches it as a control connection and
// times out. The pairing is what prevents that, so it is worth a test.
func TestWriteAdminHelloCarriesConnKind(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := proto.WriteAdminHello(&buf, proto.AdminHelloPayload{Version: proto.AdminVersion}); err != nil {
		t.Fatalf("write: %v", err)
	}

	kind, err := proto.ReadConnKind(&buf)
	if err != nil {
		t.Fatalf("read conn kind: %v", err)
	}
	if kind != proto.ConnAdmin {
		t.Fatalf("kind = %d, want ConnAdmin", kind)
	}

	typ, _, err := proto.ReadAdminFrame(&buf)
	if err != nil || typ != proto.AdminHello {
		t.Fatalf("frame after kind = %s, %v", typ, err)
	}

	// The combined write must be byte-identical to the two separate ones,
	// so a peer cannot tell which path produced it.
	var separate bytes.Buffer
	if err := proto.WriteConnKind(&separate, proto.ConnAdmin); err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteAdminFrame(&separate, proto.AdminHello,
		proto.AdminHelloPayload{Version: proto.AdminVersion}); err != nil {
		t.Fatal(err)
	}

	var combined bytes.Buffer
	if err := proto.WriteAdminHello(&combined, proto.AdminHelloPayload{Version: proto.AdminVersion}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(separate.Bytes(), combined.Bytes()) {
		t.Fatalf("combined write %x differs from separate writes %x", combined.Bytes(), separate.Bytes())
	}
}

// TestReadAdminFrameRejectsOversizePayload covers the bound that keeps a
// corrupt or hostile length prefix from making the reader allocate without
// limit. It also pins that the bound is the admin one and not the far
// smaller control-frame bound, which must not be relaxed for this plane.
func TestReadAdminFrameRejectsOversizePayload(t *testing.T) {
	t.Parallel()

	const maxAdminPayload = 1 << 20

	tests := []struct {
		name    string
		length  uint32
		wantErr bool
	}{
		{name: "at the cap", length: maxAdminPayload, wantErr: false},
		{name: "one over the cap", length: maxAdminPayload + 1, wantErr: true},
		{name: "absurd", length: ^uint32(0), wantErr: true},
		{name: "well past a control frame", length: 64 * 1024, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			header := make([]byte, 5)
			header[0] = byte(proto.AdminSnapshot)
			binary.BigEndian.PutUint32(header[1:], tt.length)

			// Only the header is supplied. An accepted length then fails
			// on the truncated body, which distinguishes "rejected the
			// length" from "tried to read the body" without ever
			// allocating a megabyte of test fixture.
			_, _, err := proto.ReadAdminFrame(bytes.NewReader(header))
			if err == nil {
				t.Fatal("truncated frame accepted")
			}
			tooLarge := strings.Contains(err.Error(), "too large")
			if tooLarge != tt.wantErr {
				t.Fatalf("err = %v, want a size rejection = %v", err, tt.wantErr)
			}
			if !tt.wantErr && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
				t.Fatalf("accepted length failed with %v, want a short-read error", err)
			}
		})
	}
}

// TestWriteAdminFrameRejectsOversizePayload is the write-side counterpart:
// a caller cannot emit a frame no conforming reader would accept.
func TestWriteAdminFrameRejectsOversizePayload(t *testing.T) {
	t.Parallel()

	// A string marshals to slightly more than its own length once quoted,
	// so exactly the cap is comfortably over it.
	huge := strings.Repeat("x", 1<<20)
	err := proto.WriteAdminFrame(io.Discard, proto.AdminResult, proto.AdminResultPayload{Detail: huge})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want a size rejection", err)
	}
}

// TestAdminTypeStringRendersUnknown covers the default arm. An admin client
// and a relay can be different builds, so a type from the future has to be
// reportable rather than rendered as a bare number with no context.
func TestAdminTypeStringRendersUnknown(t *testing.T) {
	t.Parallel()

	known := map[proto.AdminType]string{
		proto.AdminHello:     "hello",
		proto.AdminAck:       "ack",
		proto.AdminList:      "list",
		proto.AdminSnapshot:  "snapshot",
		proto.AdminKick:      "kick",
		proto.AdminReloadCRL: "reload-crl",
		proto.AdminResult:    "result",
	}
	for typ, want := range known {
		if got := typ.String(); got != want {
			t.Fatalf("AdminType(%d).String() = %q, want %q", uint8(typ), got, want)
		}
	}

	if got := proto.AdminType(200).String(); !strings.Contains(got, "200") {
		t.Fatalf("unknown type rendered as %q, want the number to survive", got)
	}
}

// TestConnAdminIsAValidKind covers the additive ConnKind in both directions.
// Adding it deliberately did not bump ALPN, so the guarantee that replaces a
// version bump is that an unknown kind is refused at the edge.
func TestConnAdminIsAValidKind(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := proto.WriteConnKind(&buf, proto.ConnAdmin); err != nil {
		t.Fatalf("write: %v", err)
	}
	kind, err := proto.ReadConnKind(&buf)
	if err != nil || kind != proto.ConnAdmin {
		t.Fatalf("round trip = %d, %v", kind, err)
	}

	if _, err := proto.ReadConnKind(bytes.NewReader([]byte{99})); err == nil {
		t.Fatal("an unknown kind was accepted")
	}
	if err := proto.WriteConnKind(io.Discard, proto.ConnKind(99)); err == nil {
		t.Fatal("an unknown kind was written")
	}
}
