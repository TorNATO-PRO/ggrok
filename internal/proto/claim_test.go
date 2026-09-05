package proto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
)

// publishHello is the Hello a publisher of creds' session would send.
func publishHello(creds proto.Credentials) proto.Hello {
	return proto.Hello{
		Role:      proto.RolePublish,
		Mode:      proto.ModeTCP,
		Ports:     2,
		SessionID: creds.SessionID(),
	}
}

func newChallenge(t *testing.T) [proto.ChallengeSize]byte {
	t.Helper()

	var challenge [proto.ChallengeSize]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}

	return challenge
}

// claimProof captures what a publisher holding creds sends in answer to
// challenge - the bytes a relay on the path, or anyone watching one, would
// have a complete and genuine copy of.
func claimProof(
	t *testing.T,
	creds proto.Credentials,
	hello proto.Hello,
	challenge [proto.ChallengeSize]byte,
) []byte {
	t.Helper()

	peer, relay := net.Pipe()
	defer func() { _ = peer.Close(); _ = relay.Close() }()
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	_ = relay.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan error, 1)
	go func() { done <- proto.ProvePublisher(peer, creds, hello) }()

	if _, err := relay.Write(challenge[:]); err != nil {
		t.Fatal(err)
	}

	proof := make([]byte, proto.PublishProofSize())
	if _, err := io.ReadFull(relay, proof); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	return proof
}

// verifyProof replays proof at a relay that will use challenge, and returns
// relay's verdict.
func verifyProof(hello proto.Hello, challenge [proto.ChallengeSize]byte, proof []byte) error {
	wire := &halfConn{r: bytes.NewReader(proof), w: io.Discard}
	return proto.VerifyPublishClaimWithChallenge(wire, hello, challenge)
}

// halfConn is a reader and a writer bolted together, for driving one side of
// an exchange whose two directions a test supplies separately.
type halfConn struct {
	r io.Reader
	w io.Writer
}

func (c *halfConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *halfConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func TestPublishClaimAcceptsTheSessionsOwner(t *testing.T) {
	t.Parallel()

	creds := newCredentials(t)
	hello := publishHello(creds)
	challenge := newChallenge(t)

	if err := verifyProof(hello, challenge, claimProof(t, creds, hello, challenge)); err != nil {
		t.Fatalf("relay rejected the session's own publisher: %v", err)
	}
}

// TestSubscriberCannotProvePublisher is the whole point of the asymmetry. A
// subscriber holds everything needed to derive the SessionID and read the
// session's traffic, and before the claim it also held everything needed to
// register as the session's publisher.
func TestSubscriberCannotProvePublisher(t *testing.T) {
	t.Parallel()

	creds := newCredentials(t)
	subscriber := creds.SubscriberToken().Credentials()

	// It knows the identifier - which is exactly why the identifier alone
	// cannot be what authorizes a publisher.
	if subscriber.SessionID() != creds.SessionID() {
		t.Fatal("subscriber does not know the SessionID; this test would prove nothing")
	}

	challenge := newChallenge(t)
	wire := &halfConn{r: bytes.NewReader(challenge[:]), w: io.Discard}

	if err := proto.ProvePublisher(wire, subscriber, publishHello(creds)); err == nil {
		t.Fatal("a subscriber produced a publish claim")
	}
}

// TestPublishClaimRejectsAnotherSessionsKey covers the claimant that can sign
// perfectly well, just not for the session it is asking for. Its signature
// verifies; the key it verifies under does not derive the claimed SessionID.
func TestPublishClaimRejectsAnotherSessionsKey(t *testing.T) {
	t.Parallel()

	target, intruder := newCredentials(t), newCredentials(t)
	challenge := newChallenge(t)

	// The Hello names the target's session; the proof is the intruder's.
	hello := publishHello(target)
	proof := claimProof(t, intruder, publishHello(intruder), challenge)

	if err := verifyProof(hello, challenge, proof); !errors.Is(err, proto.ErrPublishClaim) {
		t.Fatalf("claim under another session's key = %v, want ErrPublishClaim", err)
	}
}

// TestPublishClaimRejectsReplay is why the challenge comes from relay and is
// drawn fresh per connection: a relay, or anyone who watched one, holds a
// complete and genuine transcript of the real publisher registering.
func TestPublishClaimRejectsReplay(t *testing.T) {
	t.Parallel()

	creds := newCredentials(t)
	hello := publishHello(creds)

	recorded := claimProof(t, creds, hello, newChallenge(t))

	if err := verifyProof(hello, newChallenge(t), recorded); !errors.Is(err, proto.ErrPublishClaim) {
		t.Fatalf("replayed claim = %v, want ErrPublishClaim", err)
	}
}

// TestPublishClaimBindsTheHello covers the rest of the signed message. Even
// with the challenge held fixed, a claim made for one registration must not
// carry over to a registration describing the session differently - relay
// pairs peers by mode and port count, so a claim that floated between them
// would let a session be re-registered on terms its publisher never signed.
func TestPublishClaimBindsTheHello(t *testing.T) {
	t.Parallel()

	creds := newCredentials(t)
	hello := publishHello(creds)
	challenge := newChallenge(t)

	proof := claimProof(t, creds, hello, challenge)

	for _, altered := range []proto.Hello{
		func() proto.Hello { h := hello; h.Ports++; return h }(),
		func() proto.Hello { h := hello; h.Role = proto.RoleSubscribe; return h }(),
	} {
		if err := verifyProof(altered, challenge, proof); !errors.Is(err, proto.ErrPublishClaim) {
			t.Errorf("claim replayed onto %+v = %v, want ErrPublishClaim", altered, err)
		}
	}
}

// TestPublishClaimRejectsGarbage covers a claimant that sends bytes which are
// not an encoded key at all, which must fail closed rather than panic.
func TestPublishClaimRejectsGarbage(t *testing.T) {
	t.Parallel()

	creds := newCredentials(t)

	proof := make([]byte, proto.PublishProofSize())
	if _, err := rand.Read(proof); err != nil {
		t.Fatal(err)
	}

	err := verifyProof(publishHello(creds), newChallenge(t), proof)
	if !errors.Is(err, proto.ErrPublishClaim) {
		t.Fatalf("random proof = %v, want ErrPublishClaim", err)
	}
}
