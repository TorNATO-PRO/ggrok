package proto

import (
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// publishClaimContext domain-separates the publish claim from any other
// signature an ML-DSA key of ours might ever produce. It is passed as the
// ML-DSA context string, which both sides must supply identically for a
// signature to verify.
const publishClaimContext = "ggrok/publish-claim"

// ErrPublishClaim reports that a peer asking to publish a session could not
// prove the session is its own - a forged SessionID, a signature that does
// not verify, or a claim over the wrong challenge. It is deliberately one
// error for all three: a claimant that fails any of them is not the
// publisher, and telling it which check it tripped only helps it iterate.
var ErrPublishClaim = errors.New("publish claim rejected")

// publishProofSize is the fixed width of what a publisher sends in answer to
// the challenge: the encoded session public key followed by the signature.
// Both are fixed-width for a given parameter set, so the proof needs no
// length prefix.
func publishProofSize() int {
	params := signParams()
	return params.PublicKeySize() + params.SignatureSize()
}

// provePublisher answers relay's challenge on the publish path: it reads the
// challenge, signs the claim it forms with h, and sends the session public
// key alongside the signature so relay can check both that the key matches
// the SessionID being claimed and that the signature is the key's.
//
// The public key travels every time rather than being cached by relay. Relay
// holds no enrollment state - the first thing it learns about a session is
// someone claiming it - so there is nothing to look the key up against, and
// carrying it is what makes the claim self-contained.
func provePublisher(rw io.ReadWriter, creds Credentials, h Hello) error {
	if creds.signer == nil {
		return fmt.Errorf("prove publisher: no session key (subscriber credentials cannot publish)")
	}

	var challenge [challengeSize]byte
	if _, err := io.ReadFull(rw, challenge[:]); err != nil {
		return fmt.Errorf("read publish challenge: %w", err)
	}

	claim := publishClaim(challenge, h)
	sig, err := creds.signer.Sign(rand.Reader, claim, &mldsa.Options{Context: publishClaimContext})
	if err != nil {
		return fmt.Errorf("sign publish claim: %w", err)
	}

	// One write: the key and the signature are meaningless apart, and
	// splitting them would let a stalled peer leave relay parked mid-claim.
	proof := make([]byte, 0, publishProofSize())
	proof = append(proof, creds.signer.PublicKey().Bytes()...)
	proof = append(proof, sig...)

	if err := writeFull(rw, proof); err != nil {
		return fmt.Errorf("write publish claim: %w", err)
	}

	return nil
}

// VerifyPublishClaim is relay's half of the same exchange: it challenges the
// claimant and returns nil only if the claimant proved it holds the session
// key h.SessionID commits to.
//
// The challenge is freshly drawn per connection and single-use, and the
// signed message covers it along with the whole Hello - a signature over a
// value the claimant chose would prove nothing, and one that did not cover
// the Hello would let a recorded claim be replayed onto a session registered
// with a different mode or port count.
func VerifyPublishClaim(rw io.ReadWriter, h Hello) error {
	var challenge [challengeSize]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return fmt.Errorf("draw publish challenge: %w", err)
	}

	return verifyPublishClaim(rw, h, challenge)
}

// verifyPublishClaim is VerifyPublishClaim with the challenge supplied
// rather than drawn, which is the only way a test can present the same
// claim twice or present one against a Hello it was not made for.
func verifyPublishClaim(rw io.ReadWriter, h Hello, challenge [challengeSize]byte) error {
	if err := writeFull(rw, challenge[:]); err != nil {
		return fmt.Errorf("write publish challenge: %w", err)
	}

	params := signParams()
	proof := make([]byte, publishProofSize())
	if _, err := io.ReadFull(rw, proof); err != nil {
		return fmt.Errorf("read publish claim: %w", err)
	}

	pk, err := mldsa.NewPublicKey(params, proof[:params.PublicKeySize()])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPublishClaim, err)
	}

	// Both halves are required and neither implies the other: the SessionID
	// check says this key is the one the session is named after, and the
	// signature says the claimant actually holds its private half.
	if sessionIDFor(pk) != h.SessionID {
		return fmt.Errorf("%w: session key does not derive this session identifier", ErrPublishClaim)
	}

	claim := publishClaim(challenge, h)
	sig := proof[params.PublicKeySize():]
	if err := mldsa.Verify(pk, claim, sig, &mldsa.Options{Context: publishClaimContext}); err != nil {
		return fmt.Errorf("%w: %w", ErrPublishClaim, err)
	}

	return nil
}

// publishClaim is the message a publisher signs: relay's challenge followed
// by the exact Hello being claimed, so the signature is good for this
// connection and this registration and nothing else.
func publishClaim(challenge [challengeSize]byte, h Hello) []byte {
	hello := encodeHello(h)

	claim := make([]byte, 0, len(challenge)+len(hello))
	claim = append(claim, challenge[:]...)
	claim = append(claim, hello[:]...)
	return claim
}
