package proto

import "io"

// This file exposes the internals the crypto tests need to make assertions
// about, so those tests can live in the external proto_test package alongside
// the rest and still reach the things a caller never should.

// FrameLenSize, NoncePrefixSize and MaxFramePlaintext are the frame geometry
// tests slice and size payloads against. ChallengeSize is the width of the
// challenge relay draws for a publish claim.
const (
	FrameLenSize      = frameLenSize
	NoncePrefixSize   = noncePrefixSize
	MaxFramePlaintext = maxFramePlaintext
	ChallengeSize     = challengeSize
)

// PublishProofSize is how many bytes a publisher sends in answer to the
// challenge, so a test can read exactly one proof off a pipe.
func PublishProofSize() int { return publishProofSize() }

// ProvePublisher and VerifyPublishClaimWithChallenge are the two halves of
// the publish claim with the challenge pinned rather than drawn. Presenting
// one claim under two different challenges, or under a Hello it was not made
// for, is the whole of what these tests need to assert and is unreachable
// through the exported VerifyPublishClaim by design.
func ProvePublisher(rw io.ReadWriter, creds Credentials, h Hello) error {
	return provePublisher(rw, creds, h)
}

func VerifyPublishClaimWithChallenge(rw io.ReadWriter, h Hello, challenge [challengeSize]byte) error {
	return verifyPublishClaim(rw, h, challenge)
}

// DeriveDataKeys returns a data secret's two directional keys, so a test can
// assert directly that they differ - the invariant that keeps the two
// directions off a shared keystream.
func DeriveDataKeys(secret DataSecret) ([]byte, []byte) {
	pubToSub, subToPub := deriveDataKeys(secret)
	return pubToSub[:], subToPub[:]
}

// SessionPublicKey is the encoded session public key the credentials'
// SessionID commits to, so a test can corrupt it and confirm relay rejects a
// claim whose key does not derive the identifier being claimed.
func (c Credentials) SessionPublicKey() []byte {
	if c.signer == nil {
		return nil
	}
	return c.signer.PublicKey().Bytes()
}
