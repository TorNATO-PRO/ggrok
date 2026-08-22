package proto

// This file exposes the internals the crypto tests need to make assertions
// about, so those tests can live in the external proto_test package alongside
// the rest and still reach the things a caller never should.

// FrameLenSize and MaxFramePlaintext are the frame geometry tests slice and
// size payloads against.
const (
	FrameLenSize      = frameLenSize
	MaxFramePlaintext = maxFramePlaintext
)

// DeriveDataKeys returns a token's two directional data keys, so a test can
// assert directly that they differ - the invariant that keeps the two
// directions off a shared keystream.
func DeriveDataKeys(token Token) ([]byte, []byte) {
	pubToSub, subToPub := deriveDataKeys(token)
	return pubToSub[:], subToPub[:]
}
