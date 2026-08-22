package proto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
)

// sink is a connection whose writes land in a buffer and whose reads are
// immediately exhausted - for tests that want to inspect what a peer put on
// the wire rather than talk to a counterpart.
type sink struct{ io.Writer }

func (sink) Read([]byte) (int, error) { return 0, io.EOF }
func (sink) Close() error             { return nil }

// source replays a fixed byte stream as a connection, standing in for a relay
// handing over frames a test has assembled itself.
type source struct{ io.Reader }

func (source) Write(p []byte) (int, error) { return len(p), nil }
func (source) Close() error                { return nil }

func newToken(t *testing.T) proto.Token {
	t.Helper()

	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	return token
}

// sealed returns the frames a peer of the given role writes for plaintext.
func sealed(t *testing.T, token proto.Token, role proto.Role, plaintext []byte) []byte {
	t.Helper()

	var wire bytes.Buffer

	conn, err := proto.NewEncryptedConn(sink{&wire}, token, role)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	return wire.Bytes()
}

// pair wraps both ends of an in-memory pipe for the same token, one per role.
func pair(t *testing.T, token proto.Token) (*proto.EncryptedConn, *proto.EncryptedConn) {
	t.Helper()

	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	pub, err := proto.NewEncryptedConn(a, token, proto.RolePublish)
	if err != nil {
		t.Fatalf("NewEncryptedConn(publish): %v", err)
	}

	sub, err := proto.NewEncryptedConn(b, token, proto.RoleSubscribe)
	if err != nil {
		t.Fatalf("NewEncryptedConn(subscribe): %v", err)
	}

	return pub, sub
}

func TestDirectionalKeysDiffer(t *testing.T) {
	t.Parallel()

	pubToSub, subToPub := proto.DeriveDataKeys(newToken(t))

	// The two directions must not share a key. Both peers number their frames
	// from zero, so one shared key would put both first frames under the same
	// key and nonce - see TestOppositeDirectionsDoNotShareKeystream for what
	// that costs.
	if bytes.Equal(pubToSub, subToPub) {
		t.Fatal("both directions derived the same data key: keystream reuse")
	}
}

func TestDerivationIsDeterministicPerToken(t *testing.T) {
	t.Parallel()

	token, other := newToken(t), newToken(t)

	first, again := proto.DeriveSessionID(token), proto.DeriveSessionID(token)
	if first != again {
		t.Error("DeriveSessionID is not deterministic")
	}
	if first == proto.DeriveSessionID(other) {
		t.Error("distinct tokens collided on one SessionID")
	}
}

func TestSessionLogTagIsTruncated(t *testing.T) {
	t.Parallel()

	id := proto.DeriveSessionID(newToken(t))

	// The SessionID is what a peer presents to attach to a session, so a log
	// line must not carry enough of it to replay.
	const fullyRendered = proto.SessionIDSize * 2 // hex is two chars a byte

	if tag := id.LogTag(); len(tag) >= fullyRendered {
		t.Errorf("LogTag renders %d of %d hex chars; it must truncate", len(tag), fullyRendered)
	}
}

// TestOppositeDirectionsDoNotShareKeystream is the regression test for the
// keystream reuse this layer originally shipped with: both peers derived one
// key and both started at counter zero, so XORing their first two ciphertexts
// recovered the XOR of the two plaintexts.
func TestOppositeDirectionsDoNotShareKeystream(t *testing.T) {
	t.Parallel()

	token := newToken(t)

	pubPlain := []byte("GET /secret HTTP/1.1")
	subPlain := []byte("HTTP/1.1 200 OK\r\n\r\n")

	c1 := sealed(t, token, proto.RolePublish, pubPlain)[proto.FrameLenSize:]
	c2 := sealed(t, token, proto.RoleSubscribe, subPlain)[proto.FrameLenSize:]

	for i := range min(len(pubPlain), len(subPlain)) {
		// Under one shared keystream this reconstructs pubPlain exactly.
		if c1[i]^c2[i]^subPlain[i] != pubPlain[i] {
			return // keystreams differ, as they must
		}
	}

	t.Fatal("ciphertext XOR recovered plaintext: the two directions share a keystream")
}

func TestEncryptedConnRoundTrip(t *testing.T) {
	t.Parallel()

	token := newToken(t)

	// Sizes that straddle a frame boundary, so the split in Write and the
	// carry-over buffer in Read both get exercised.
	sizes := []int{
		1,
		100,
		proto.MaxFramePlaintext - 1,
		proto.MaxFramePlaintext,
		proto.MaxFramePlaintext + 1,
		3 * proto.MaxFramePlaintext,
	}

	for _, size := range sizes {
		want := make([]byte, size)
		if _, err := rand.Read(want); err != nil {
			t.Fatal(err)
		}

		pub, sub := pair(t, token)

		go func() {
			if _, writeErr := pub.Write(want); writeErr != nil {
				t.Errorf("write %d bytes: %v", size, writeErr)
			}
			_ = pub.Close()
		}()

		got, err := io.ReadAll(sub)
		if err != nil {
			t.Fatalf("read %d bytes: %v", size, err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("round trip of %d bytes did not match (got %d bytes)", size, len(got))
		}
	}
}

// TestReadReassemblesAcrossSmallBuffers covers what a real tunnel hits: one
// large frame drained by a reader with a much smaller buffer.
func TestReadReassemblesAcrossSmallBuffers(t *testing.T) {
	t.Parallel()

	want := make([]byte, 8192)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}

	pub, sub := pair(t, newToken(t))

	go func() {
		_, _ = pub.Write(want)
		_ = pub.Close()
	}()

	var got []byte
	buf := make([]byte, 7) // deliberately awkward
	for {
		n, err := sub.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("read: %v", err)
		}
	}

	if !bytes.Equal(got, want) {
		t.Errorf("reassembled %d bytes, want %d", len(got), len(want))
	}
}

func TestTamperedFrameIsRejected(t *testing.T) {
	t.Parallel()

	token := newToken(t)

	frame := sealed(t, token, proto.RolePublish, []byte("transfer $10 to alice"))
	frame[len(frame)-1] ^= 0x01 // flip a bit in the tag

	sub, err := proto.NewEncryptedConn(source{bytes.NewReader(frame)}, token, proto.RoleSubscribe)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sub.Read(make([]byte, 64)); err == nil {
		t.Fatal("tampered frame decrypted without error")
	}
}

// TestReplayedFrameIsRejected checks that the frame counter really does bind a
// frame to its position: relay sits in the middle of this stream and must not
// be able to duplicate a frame it forwarded.
func TestReplayedFrameIsRejected(t *testing.T) {
	t.Parallel()

	token := newToken(t)

	frame := sealed(t, token, proto.RolePublish, []byte("withdraw"))
	replayed := append(bytes.Clone(frame), frame...)

	sub, err := proto.NewEncryptedConn(source{bytes.NewReader(replayed)}, token, proto.RoleSubscribe)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	if _, err := sub.Read(buf); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	if _, err := sub.Read(buf); err == nil {
		t.Fatal("replayed frame accepted at the next counter")
	}
}

// TestWrongTokenCannotDecrypt is the property relay depends on: it pairs two
// peers by SessionID and can still read nothing they send.
func TestWrongTokenCannotDecrypt(t *testing.T) {
	t.Parallel()

	frame := sealed(t, newToken(t), proto.RolePublish, []byte("secret"))

	eavesdropper, err := proto.NewEncryptedConn(source{bytes.NewReader(frame)}, newToken(t), proto.RoleSubscribe)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := eavesdropper.Read(make([]byte, 64)); err == nil {
		t.Fatal("a different token decrypted the frame")
	}
}

// TestSameRoleBothEndsFails guards the constructor's contract: two peers that
// pass the same role write with the same key and cannot read each other.
func TestSameRoleBothEndsFails(t *testing.T) {
	t.Parallel()

	token := newToken(t)
	frame := sealed(t, token, proto.RolePublish, []byte("hello"))

	same, err := proto.NewEncryptedConn(source{bytes.NewReader(frame)}, token, proto.RolePublish)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := same.Read(make([]byte, 64)); err == nil {
		t.Fatal("a peer with the same role decrypted the frame")
	}
}
