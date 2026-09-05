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

// newSecret draws a fresh data secret. The frame codec cares only about the
// secret its keys come from, so these tests take one directly rather than
// deriving one from a session key.
func newSecret(t *testing.T) proto.DataSecret {
	t.Helper()

	var secret proto.DataSecret
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}

	return secret
}

// newCredentials derives a fresh publisher's credentials, for the tests that
// need a whole session rather than just a stream key.
func newCredentials(t *testing.T) proto.Credentials {
	t.Helper()

	key, err := proto.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}

	creds, err := key.Credentials()
	if err != nil {
		t.Fatal(err)
	}

	return creds
}

// body strips a stream's nonce prefix and its first frame's length prefix,
// leaving the ciphertext itself - what a test XORs against another stream's.
func body(wire []byte) []byte {
	return wire[proto.NoncePrefixSize+proto.FrameLenSize:]
}

// sealed returns the frames a peer of the given role writes for plaintext,
// led by the stream's nonce prefix as it goes out on the wire.
func sealed(t *testing.T, secret proto.DataSecret, role proto.Role, plaintext []byte) []byte {
	t.Helper()

	var wire bytes.Buffer

	conn, err := proto.NewEncryptedConn(sink{&wire}, secret, role)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	return wire.Bytes()
}

// pair wraps both ends of an in-memory pipe for the same secret, one per role.
func pair(t *testing.T, secret proto.DataSecret) (*proto.EncryptedConn, *proto.EncryptedConn) {
	t.Helper()

	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	pub, err := proto.NewEncryptedConn(a, secret, proto.RolePublish)
	if err != nil {
		t.Fatalf("NewEncryptedConn(publish): %v", err)
	}

	sub, err := proto.NewEncryptedConn(b, secret, proto.RoleSubscribe)
	if err != nil {
		t.Fatalf("NewEncryptedConn(subscribe): %v", err)
	}

	return pub, sub
}

func TestDirectionalKeysDiffer(t *testing.T) {
	t.Parallel()

	pubToSub, subToPub := proto.DeriveDataKeys(newSecret(t))

	// The two directions must not share a key. Both peers number their frames
	// from zero, so one shared key would put both first frames under the same
	// key and nonce - see TestOppositeDirectionsDoNotShareKeystream for what
	// that costs.
	if bytes.Equal(pubToSub, subToPub) {
		t.Fatal("both directions derived the same data key: keystream reuse")
	}
}

// TestDerivationIsDeterministicPerSessionKey is what makes a session key
// reusable: the same key has to keep producing the same SessionID and the
// same subscriber token, or every restart of share would invalidate every
// token already handed out.
func TestDerivationIsDeterministicPerSessionKey(t *testing.T) {
	t.Parallel()

	key, err := proto.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}

	first, err := key.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	again, err := key.Credentials()
	if err != nil {
		t.Fatal(err)
	}

	if first.SessionID() != again.SessionID() {
		t.Error("one session key derived two SessionIDs")
	}
	if first.SubscriberToken() != again.SubscriberToken() {
		t.Error("one session key derived two subscriber tokens")
	}
	if other := newCredentials(t); first.SessionID() == other.SessionID() {
		t.Error("distinct session keys collided on one SessionID")
	}
}

// TestSubscriberTokenCarriesNoSigningKey is the property the whole publish
// claim rests on. A subscriber token round-trips to credentials that can join
// the session and read its traffic, and to nothing that can sign for it.
func TestSubscriberTokenCarriesNoSigningKey(t *testing.T) {
	t.Parallel()

	pub := newCredentials(t)
	sub := pub.SubscriberToken().Credentials()

	if sub.SessionID() != pub.SessionID() {
		t.Fatal("subscriber token names a different session than the key it came from")
	}
	if sub.SubscriberToken() != pub.SubscriberToken() {
		t.Fatal("subscriber token did not round-trip")
	}
	if sub.SessionPublicKey() != nil {
		t.Fatal("subscriber credentials carry a signing key")
	}
	if pub.SessionPublicKey() == nil {
		t.Fatal("publisher credentials carry no signing key")
	}
}

// TestSubscriberTokenParsesRoundTrip also pins the two secrets apart by
// length, which is how someone who pasted the wrong one finds out.
func TestSubscriberTokenParsesRoundTrip(t *testing.T) {
	t.Parallel()

	creds := newCredentials(t)
	token := creds.SubscriberToken()

	parsed, err := proto.ParseSubscriberToken(token.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != token {
		t.Fatal("subscriber token did not survive String/Parse")
	}

	key, err := proto.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proto.ParseSubscriberToken(key.String()); err == nil {
		t.Error("a session key parsed as a subscriber token")
	}
	if _, err := proto.ParseSessionKey(token.String()); err == nil {
		t.Error("a subscriber token parsed as a session key")
	}
}

func TestSessionLogTagIsTruncated(t *testing.T) {
	t.Parallel()

	id := newCredentials(t).SessionID()

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

	secret := newSecret(t)

	pubPlain := []byte("GET /secret HTTP/1.1")
	subPlain := []byte("HTTP/1.1 200 OK\r\n\r\n")

	c1 := body(sealed(t, secret, proto.RolePublish, pubPlain))
	c2 := body(sealed(t, secret, proto.RoleSubscribe, subPlain))

	for i := range min(len(pubPlain), len(subPlain)) {
		// Under one shared keystream this reconstructs pubPlain exactly.
		if c1[i]^c2[i]^subPlain[i] != pubPlain[i] {
			return // keystreams differ, as they must
		}
	}

	t.Fatal("ciphertext XOR recovered plaintext: the two directions share a keystream")
}

// TestStreamsDoNotShareKeystream is the same property one scope out, and the
// regression test for the reuse that survived the directional fix: the data
// keys are a pure function of the secret, so every stream sharing one shares
// them, and every stream numbers its frames from zero. Two streams in the
// same direction - two subscribers, or one that connects twice, or one
// connection after another - therefore sealed their first frames under the
// same key and nonce until each stream drew a nonce prefix of its own.
//
// relay is the party this matters against: it sees every stream's ciphertext
// and is precisely who the end-to-end layer exists to exclude.
func TestStreamsDoNotShareKeystream(t *testing.T) {
	t.Parallel()

	secret := newSecret(t)

	first := []byte("GET /alice HTTP/1.1")
	second := []byte("GET /bob   HTTP/1.1")

	// Same secret, same role, same session: two forwarded connections.
	c1 := body(sealed(t, secret, proto.RolePublish, first))
	c2 := body(sealed(t, secret, proto.RolePublish, second))

	for i := range min(len(first), len(second)) {
		// Under one shared keystream this reconstructs first exactly, so a
		// single byte that survives the XOR proves the streams diverged.
		if c1[i]^c2[i]^second[i] != first[i] {
			return
		}
	}

	t.Fatal("ciphertext XOR recovered plaintext: two streams in one session share a keystream")
}

// TestStreamNoncePrefixesDiffer asserts the mechanism the test above measures
// the effect of, so a regression names itself instead of surfacing as a
// statistical claim about XORed bytes.
func TestStreamNoncePrefixesDiffer(t *testing.T) {
	t.Parallel()

	secret := newSecret(t)

	first := sealed(t, secret, proto.RolePublish, []byte("x"))[:proto.NoncePrefixSize]
	second := sealed(t, secret, proto.RolePublish, []byte("x"))[:proto.NoncePrefixSize]

	if bytes.Equal(first, second) {
		t.Fatal("two streams drew the same nonce prefix")
	}

	if bytes.Equal(first, make([]byte, proto.NoncePrefixSize)) {
		t.Fatal("nonce prefix is all zeros: it was never drawn")
	}
}

func TestEncryptedConnRoundTrip(t *testing.T) {
	t.Parallel()

	secret := newSecret(t)

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

		pub, sub := pair(t, secret)

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

	pub, sub := pair(t, newSecret(t))

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

	secret := newSecret(t)

	frame := sealed(t, secret, proto.RolePublish, []byte("transfer $10 to alice"))
	frame[len(frame)-1] ^= 0x01 // flip a bit in the tag

	sub, err := proto.NewEncryptedConn(source{bytes.NewReader(frame)}, secret, proto.RoleSubscribe)
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

	secret := newSecret(t)

	// The prefix is sent once per stream, so the duplicate is the frame
	// alone - a replay relay could mount by resending bytes it forwarded.
	frame := sealed(t, secret, proto.RolePublish, []byte("withdraw"))
	replayed := append(bytes.Clone(frame), frame[proto.NoncePrefixSize:]...)

	sub, err := proto.NewEncryptedConn(source{bytes.NewReader(replayed)}, secret, proto.RoleSubscribe)
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

	frame := sealed(t, newSecret(t), proto.RolePublish, []byte("secret"))

	eavesdropper, err := proto.NewEncryptedConn(source{bytes.NewReader(frame)}, newSecret(t), proto.RoleSubscribe)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := eavesdropper.Read(make([]byte, 64)); err == nil {
		t.Fatal("a different secret decrypted the frame")
	}
}

// TestSameRoleBothEndsFails guards the constructor's contract: two peers that
// pass the same role write with the same key and cannot read each other.
func TestSameRoleBothEndsFails(t *testing.T) {
	t.Parallel()

	secret := newSecret(t)
	frame := sealed(t, secret, proto.RolePublish, []byte("hello"))

	same, err := proto.NewEncryptedConn(source{bytes.NewReader(frame)}, secret, proto.RolePublish)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := same.Read(make([]byte, 64)); err == nil {
		t.Fatal("a peer with the same role decrypted the frame")
	}
}

func TestReadAcrossChangingFrameSizes(t *testing.T) {
	t.Parallel()
	secret := newSecret(t)
	var wire, want bytes.Buffer
	writer, err := proto.NewEncryptedConn(sink{&wire}, secret, proto.RolePublish)
	if err != nil {
		t.Fatal(err)
	}
	for i, size := range []int{1, 32768, 3, proto.MaxFramePlaintext, 19} {
		data := bytes.Repeat([]byte{byte(i + 1)}, size)
		want.Write(data)
		if _, writeErr := writer.Write(data); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	reader, err := proto.NewEncryptedConn(source{&wire}, secret, proto.RoleSubscribe)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	buf := make([]byte, 7)
	for {
		n, err := reader.Read(buf)
		got.Write(buf[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatal("frame buffer reuse corrupted partial reads")
	}
}

// BenchmarkEncryptedRead includes per-stream setup and decryption of 1 MiB.
func BenchmarkEncryptedRead(b *testing.B) {
	var secret proto.DataSecret
	var wire bytes.Buffer
	writer, err := proto.NewEncryptedConn(sink{&wire}, secret, proto.RolePublish)
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{42}, 1<<20)
	if _, err := writer.Write(payload); err != nil {
		b.Fatal(err)
	}
	raw := wire.Bytes()
	buf := make([]byte, 4096)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		reader, err := proto.NewEncryptedConn(source{bytes.NewReader(raw)}, secret, proto.RoleSubscribe)
		if err != nil {
			b.Fatal(err)
		}
		total := 0
		for {
			n, err := reader.Read(buf)
			total += n
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
		}
		if total != len(payload) {
			b.Fatalf("read %d bytes", total)
		}
	}
}
