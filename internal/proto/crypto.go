package proto

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// A session key is the root secret of a session, and everything else is
// derived from it with HKDF-SHA256, each derivation bound to a distinct info
// string so none of them can be computed from another:
//
//   - the ML-DSA seed, and so the keypair whose public half the SessionID
//     commits to (see signSeedInfo and sessionIDFor);
//   - the data secret, which is what a subscriber is given and what the two
//     directional AEAD keys and the tunnel proofs come from.
//
// The SessionID is derived from the public key rather than from the session
// key directly, so that knowing the identifier relay routes by says nothing
// about the key that claims it - which is the whole basis of the publish
// claim.
const (
	signSeedInfo   = "ggrok/publisher-sign"
	dataSecretInfo = "ggrok/data" //nolint:gosec // an HKDF info string, not a credential
	sessionIDInfo  = "ggrok/session-id"
	pubKeyInfo     = "ggrok data key publisher->subscriber"
	subKeyInfo     = "ggrok data key subscriber->publisher"
)

// SessionIDSize is the width of a SessionID in bytes, and DataSecretSize the
// width of a DataSecret. Together they are what a SubscriberToken carries.
const (
	SessionIDSize  = 16
	DataSecretSize = 16
)

// signParams is the ML-DSA parameter set a publisher's session keypair uses.
// ML-DSA-65 matches what the CA issues device certificates under, so a
// deployment has one post-quantum signature primitive rather than two.
func signParams() mldsa.Parameters { return mldsa.MLDSA65() }

// SessionID is the identifier relay pairs a publisher and its subscribers by.
// It is derived from the publisher's session public key and travels in Hello
// and Attach, so relay can route a session without holding any secret that
// would let it join or decrypt one.
//
// It is not a public value: anyone holding it and a certificate from the same
// CA can attach to the session as a subscriber. They cannot read anything -
// the data keys are not derivable from it - nor publish, since claiming the
// publisher slot takes a signature under the key this ID commits to. But they
// can consume a slot, so treat it as sensitive and log only a truncated form
// (see LogTag).
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

// DataSecret is the secret both ends of a session hold: the tunnel proofs and
// the two directional AEAD keys are derived from it, and it is the half of a
// SubscriberToken that is not the SessionID. Relay never holds one.
type DataSecret [DataSecretSize]byte

// Credentials is everything one peer needs for one session: the SessionID
// relay routes by, the data secret that seals the tunnel, and - for a
// publisher only - the signing key that proves the session is its own.
//
// The asymmetry is the point. Both ends can talk through the session, and
// only the end that holds the session key can claim it, so a subscriber
// cannot take the publisher slot when the real publisher's connection drops.
type Credentials struct {
	id   SessionID
	data DataSecret

	// signer is nil for a subscriber, which is exactly what it cannot
	// reconstruct from anything it holds.
	signer *mldsa.PrivateKey
}

// Credentials derives the publisher's credentials for k's session.
//
// The keypair is derived rather than generated, so the same session key keeps
// producing the same SessionID across restarts - tokens handed out yesterday
// still work today, which an ephemeral per-run keypair would break every time
// share was restarted.
func (k SessionKey) Credentials() (Credentials, error) {
	var seed [mldsa.PrivateKeySize]byte
	deriveKey(k[:], signSeedInfo, seed[:])

	signer, err := mldsa.NewPrivateKey(signParams(), seed[:])
	if err != nil {
		return Credentials{}, fmt.Errorf("derive session signing key: %w", err)
	}

	var data DataSecret
	deriveKey(k[:], dataSecretInfo, data[:])

	return Credentials{id: sessionIDFor(signer.PublicKey()), data: data, signer: signer}, nil
}

// Credentials unpacks the subscriber's credentials carried in t. Unlike the
// publisher's, this cannot fail and cannot produce a signer: a subscriber
// token is only ever the two values it already contains.
func (t SubscriberToken) Credentials() Credentials {
	var c Credentials
	copy(c.data[:], t[:DataSecretSize])
	copy(c.id[:], t[DataSecretSize:])
	return c
}

// SessionID is the identifier these credentials name to relay.
func (c Credentials) SessionID() SessionID { return c.id }

// SubscriberToken renders what a subscriber needs to join this session: the
// data secret and the SessionID, and deliberately nothing that can sign.
func (c Credentials) SubscriberToken() SubscriberToken {
	var t SubscriberToken
	copy(t[:DataSecretSize], c.data[:])
	copy(t[DataSecretSize:], c.id[:])
	return t
}

// sessionIDFor derives the SessionID a publisher's session public key
// commits to. Relay recomputes it from the key a claimant presents, so a
// forged claim needs a second preimage on a 128-bit hash while holding the
// matching private key.
func sessionIDFor(pk *mldsa.PublicKey) SessionID {
	digest := sha256.Sum256(pk.Bytes())

	var id SessionID
	deriveKey(digest[:], sessionIDInfo, id[:])
	return id
}

// dataKey is the ChaCha20-Poly1305 key protecting one direction of a
// session's forwarded traffic. It is derived from the data secret and never
// leaves the peer that derived it.
type dataKey [chacha20poly1305.KeySize]byte

// deriveDataKeys returns secret's two directional keys: one for frames
// travelling publisher-to-subscriber, one for the reverse.
//
// The two directions must not share a key. ChaCha20 is a stream cipher and
// the nonce is a per-direction frame counter starting at zero, so a single
// shared key would have both peers encrypting their first frame under the
// same key and nonce - XORing the two ciphertexts would then recover the XOR
// of the plaintexts, and the reused Poly1305 one-time key would make frames
// forgeable. Separate keys make the two counter sequences independent.
func deriveDataKeys(secret DataSecret) (dataKey, dataKey) {
	var pubToSub, subToPub dataKey
	deriveKey(secret[:], pubKeyInfo, pubToSub[:])
	deriveKey(secret[:], subKeyInfo, subToPub[:])
	return pubToSub, subToPub
}

// deriveKey fills out with HKDF-SHA256 output over secret, bound to info.
func deriveKey(secret []byte, info string, out []byte) {
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(info)), out); err != nil {
		// HKDF-SHA256 is a pure function of its inputs and out is far
		// shorter than the 255*32 bytes it can produce, so this cannot fail.
		panic(fmt.Sprintf("derive %s: %v", info, err))
	}
}
