package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// A token is the root secret of a session, and three independent values are
// derived from it with HKDF-SHA256: the SessionID relay routes by, and one
// data key per direction. Each derivation uses a distinct info string, so
// none of them can be computed from another - relay learns the SessionID and
// still cannot decrypt a byte.
const (
	sessionIDInfo = "ggrok session id"
	pubKeyInfo    = "ggrok data key publisher->subscriber"
	subKeyInfo    = "ggrok data key subscriber->publisher"
)

// SessionIDSize is the width of a SessionID in bytes. It matches tokenSize so
// swapping the token for its SessionID left every wire message the same size.
const SessionIDSize = 16

// SessionID is the identifier relay pairs a publisher and its subscribers by.
// It is derived from a session's token and travels in Hello and Attach in the
// token's place, so relay can route a session without ever holding the bearer
// secret that would let it join or decrypt one.
//
// It is not a public value: anyone holding it and a certificate from the same
// CA can attach to the session as a subscriber. They cannot read anything -
// the data keys are not derivable from it - but they can consume a slot, so
// treat it as sensitive and log only a truncated form (see LogTag).
type SessionID [SessionIDSize]byte

// sessionLogTagBytes is how much of a SessionID LogTag renders. Six bytes is
// far too little to attach to a session with and far more than enough to keep
// concurrent sessions distinguishable in a log.
const sessionLogTagBytes = 6

// LogTag renders enough of the SessionID to tie a publisher, its subscribers
// and their streams together across log lines, and no more - the whole value
// is a credential for attaching to the session, so it never goes to a log.
func (s SessionID) LogTag() string {
	return hex.EncodeToString(s[:sessionLogTagBytes])
}

// DeriveSessionID derives token's relay-visible routing identifier.
func DeriveSessionID(token Token) SessionID {
	var id SessionID
	deriveKey(token, sessionIDInfo, id[:])
	return id
}

// dataKey is the ChaCha20-Poly1305 key protecting one direction of a
// session's forwarded traffic. It is derived from the token and never leaves
// the peer that derived it.
type dataKey [chacha20poly1305.KeySize]byte

// deriveDataKeys returns token's two directional keys: one for frames
// travelling publisher-to-subscriber, one for the reverse.
//
// The two directions must not share a key. ChaCha20 is a stream cipher and
// the nonce is a per-direction frame counter starting at zero, so a single
// shared key would have both peers encrypting their first frame under the
// same key and nonce - XORing the two ciphertexts would then recover the XOR
// of the plaintexts, and the reused Poly1305 one-time key would make frames
// forgeable. Separate keys make the two counter sequences independent.
func deriveDataKeys(token Token) (dataKey, dataKey) {
	var pubToSub, subToPub dataKey
	deriveKey(token, pubKeyInfo, pubToSub[:])
	deriveKey(token, subKeyInfo, subToPub[:])
	return pubToSub, subToPub
}

// deriveKey fills out with HKDF-SHA256 output over token, bound to info.
func deriveKey(token Token, info string, out []byte) {
	if _, err := io.ReadFull(hkdf.New(sha256.New, token[:], nil, []byte(info)), out); err != nil {
		// HKDF-SHA256 is a pure function of its inputs and out is far
		// shorter than the 255*32 bytes it can produce, so this cannot fail.
		panic(fmt.Sprintf("derive %s: %v", info, err))
	}
}
