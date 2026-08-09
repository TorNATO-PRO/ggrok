// Package proto is the tiny control-plane wire format shared by share,
// listen, and relay: the token that scopes a subscriber to one publisher's
// session, and the Hello handshake a peer sends relay to identify itself.
package proto

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
)

// tokenSize is the width of a Token in bytes.
// Remember that a byte is 8 bits :).
const tokenSize = 16

// tokenEncoding renders a Token as lowercase, unpadded base32 - shorter and
// more copy/paste friendly than hex, and case-insensitive unlike base64.
var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Token is the bearer secret that scopes a listen subscriber to one share's
// session. Anyone holding it (and an mTLS cert signed by the same CA) can
// subscribe to that session, so it must be unguessable and shared out of
// band, not chosen by the operator.
type Token [tokenSize]byte

// NewToken draws a fresh, cryptographically random token.
func NewToken() (Token, error) {
	var t Token
	if _, err := rand.Read(t[:]); err != nil {
		return Token{}, fmt.Errorf("generate token: %w", err)
	}

	return t, nil
}

// String renders the token for display and for passing on a command line.
func (t Token) String() string {
	return tokenEncoding.EncodeToString(t[:])
}

// ParseToken parses a token previously rendered by String.
func ParseToken(s string) (Token, error) {
	decoded, err := tokenEncoding.DecodeString(s)
	if err != nil {
		return Token{}, fmt.Errorf("parse token: %w", err)
	}

	if len(decoded) != tokenSize {
		return Token{}, fmt.Errorf("parse token: want %d bytes, got %d", tokenSize, len(decoded))
	}

	var t Token
	copy(t[:], decoded)
	return t, nil
}
