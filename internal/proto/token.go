// Package proto is the wire format shared by share, listen, and relay: the
// session key a publisher holds, the subscriber token derived from it (see
// crypto.go), the Hello and Attach a peer sends relay to identify itself, and
// the control frames that keep a session alive.
//
// It also owns the data plane's encryption (see EncryptedConn), because the
// split between what relay may read and what only the two peers may read is a
// property of this wire format rather than of either peer.
package proto

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
)

// SessionKeySize is the width of a SessionKey in bytes, and
// SubscriberTokenSize the width of a SubscriberToken. A subscriber token is
// the data secret followed by the SessionID it belongs to, both derived from
// the session key.
//
// Remember that a byte is 8 bits :).
const (
	SessionKeySize      = 16
	SubscriberTokenSize = DataSecretSize + SessionIDSize
)

// tokenEncoding renders a session key or subscriber token as uppercase,
// unpadded base32 - 26 characters for the first, 52 for the second.
var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// SessionKey is the root secret of a session and belongs to its publisher
// alone. Everything else is derived from it (see Credentials): the ML-DSA
// keypair that proves to relay this session is ours, the SessionID relay
// routes by, and the data secret sealing the tunnel.
//
// It is not the value you hand out. A holder of the session key can publish
// the session - that is the whole point of it - so a subscriber gets the
// SubscriberToken derived from it instead, which carries no ability to sign.
// Keep the key, share the token.
type SessionKey [SessionKeySize]byte

// NewSessionKey draws a fresh, cryptographically random session key.
func NewSessionKey() (SessionKey, error) {
	var k SessionKey
	if _, err := rand.Read(k[:]); err != nil {
		return SessionKey{}, fmt.Errorf("generate session key: %w", err)
	}

	return k, nil
}

// String renders the session key for display and for passing on a command
// line.
func (k SessionKey) String() string {
	return tokenEncoding.EncodeToString(k[:])
}

// ParseSessionKey parses a session key previously rendered by String.
func ParseSessionKey(s string) (SessionKey, error) {
	var k SessionKey
	if err := decodeSecret(s, k[:]); err != nil {
		return SessionKey{}, fmt.Errorf("parse session key: %w", err)
	}

	return k, nil
}

// SubscriberToken is the bearer secret that scopes a listen subscriber to one
// publisher's session: the session's data secret and the SessionID relay
// routes it by, concatenated. Anyone holding it (and an mTLS cert signed by
// the same CA) can subscribe to that session and read its traffic, so it must
// be shared out of band rather than chosen by the operator.
//
// What it deliberately does not carry is the session key, so a subscriber
// cannot sign relay's publish challenge and therefore cannot take the
// publisher slot - see Credentials and VerifyPublishClaim.
type SubscriberToken [SubscriberTokenSize]byte

// String renders the subscriber token for display and for passing on a
// command line.
func (t SubscriberToken) String() string {
	return tokenEncoding.EncodeToString(t[:])
}

// ParseSubscriberToken parses a subscriber token previously rendered by
// String.
func ParseSubscriberToken(s string) (SubscriberToken, error) {
	var t SubscriberToken
	if err := decodeSecret(s, t[:]); err != nil {
		return SubscriberToken{}, fmt.Errorf("parse subscriber token: %w", err)
	}

	return t, nil
}

// decodeSecret decodes s into out, which must be exactly the width the
// encoded form carries. The length check is what tells someone who pasted a
// session key where a subscriber token belongs - or the reverse - which of
// the two they are holding, since both are base32 of the same alphabet and
// differ only in size.
func decodeSecret(s string, out []byte) error {
	decoded, err := tokenEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	if len(decoded) != len(out) {
		return fmt.Errorf("want %d bytes, got %d", len(out), len(decoded))
	}

	copy(out, decoded)
	return nil
}
