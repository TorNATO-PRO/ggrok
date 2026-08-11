// Package udpcrypto is the per-packet AEAD encryption UDP-mode tunnels use
// in place of QUIC's built-in per-datagram TLS 1.3 protection. Go's
// standard library has no DTLS equivalent for plain UDP, so this package
// derives a symmetric key from an already-mutually-authenticated TLS
// connection (via RFC 5705 keying-material export - no new handshake or
// key exchange of its own) and uses it to seal/open individual datagrams,
// with a sliding replay window standing in for what a stream transport's
// ordering guarantees would otherwise rule out for free.
package udpcrypto

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"

	"tornato.dev/ggrok/v2/internal/proto"
)

// keyLabel is the label passed to (*tls.ConnectionState).ExportKeyingMaterial
// for every UDP-mode AEAD key derived in this package (RFC 5705).
const keyLabel = "ggrok udp-mode data key"

// KeySize is chacha20poly1305's key size.
const KeySize = chacha20poly1305.KeySize

// Direction distinguishes the two directions of one hop's traffic, so
// their AEAD keys - and therefore their nonce spaces - never collide even
// though both are derived from the same underlying TLS connection.
type Direction byte

const (
	// DirectionUplink keys traffic traveling toward relay (share/listen
	// -> relay).
	DirectionUplink Direction = iota + 1

	// DirectionDownlink keys traffic traveling away from relay
	// (relay -> share/listen).
	DirectionDownlink
)

// DeriveKey derives a KeySize-byte AEAD key from state, bound to routing,
// token, and direction so the same key can never be reused across
// sessions, hops, or directions. Both ends of the same TLS connection
// derive identical output for identical inputs (that's the point of a
// TLS exporter - see RFC 5705), so no key material ever crosses the wire.
//
// state must belong to a TLS 1.3 connection - internal/mtls.LoadConfig
// always pins MinVersion to TLS 1.3, so this is guaranteed for every
// connection ggrok itself establishes; ExportKeyingMaterial errors
// otherwise.
func DeriveKey(
	state *tls.ConnectionState,
	routing proto.RoutingID,
	token proto.Token,
	direction Direction,
) ([KeySize]byte, error) {
	tokenHash := sha256.Sum256(token[:])

	context := make([]byte, 0, len(routing)+len(tokenHash)+1)
	context = append(context, routing[:]...)
	context = append(context, tokenHash[:]...)
	context = append(context, byte(direction))

	material, err := state.ExportKeyingMaterial(keyLabel, context, KeySize)
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("derive udp key: %w", err)
	}

	var key [KeySize]byte
	copy(key[:], material)
	return key, nil
}

// NewAEAD builds a chacha20poly1305 [cipher.AEAD] from a key derived by
// DeriveKey.
func NewAEAD(key [KeySize]byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}

	return aead, nil
}

// headerSize is the wire overhead before the AEAD-sealed payload: an
// 8-byte RoutingID (proto.RoutingID) followed by an 8-byte counter, which
// doubles as the AEAD nonce's variable component. Both travel in the
// clear - the RoutingID so relay can pick which session's key to try
// before it can decrypt anything, the counter so a receiver can check it
// against its replay window before decrypting.
const headerSize = 8 + 8

// nonceFor renders counter as chacha20poly1305's 12-byte nonce: 4 zero
// bytes followed by the big-endian counter. Never reusing a (key, nonce)
// pair is the AEAD's entire security property, which is exactly what a
// strictly monotonic per-direction counter guarantees as long as it's
// never allowed to wrap - see Session's uint64 counter, whose range makes
// that a non-concern in practice.
func nonceFor(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// Seal frames and encrypts plaintext into a wire-format datagram:
// [8B RoutingID][8B counter][AEAD-sealed plaintext, authenticating the
// header as associated data]. counter must never repeat for the same
// aead - see Session.Send and relay's udpRouter for the two ways this
// package's callers guarantee that.
func Seal(aead cipher.AEAD, routing proto.RoutingID, counter uint64, plaintext []byte) []byte {
	header := make([]byte, headerSize, headerSize+len(plaintext)+aead.Overhead())
	copy(header, routing[:])
	binary.BigEndian.PutUint64(header[len(routing):], counter)

	return aead.Seal(header, nonceFor(counter), plaintext, header)
}

// Open reverses Seal: it decrypts and authenticates datagram (a complete
// wire-format datagram, RoutingID included - callers that already peeled
// the RoutingID off to pick this aead/window in the first place can
// simply pass the original bytes through unmodified), rejecting it
// outright if its counter is a replay or too old for window to trust.
// The replay window is only updated on a successful open, so a forged
// datagram can never be used to poison it against a legitimate one that
// hasn't arrived yet.
func Open(aead cipher.AEAD, window *ReplayWindow, datagram []byte) ([]byte, error) {
	if len(datagram) < headerSize {
		return nil, fmt.Errorf("open: short datagram (%d bytes)", len(datagram))
	}

	header := datagram[:headerSize]
	counter := binary.BigEndian.Uint64(header[8:])

	if window.Seen(counter) {
		return nil, fmt.Errorf("open: replayed or stale counter %d", counter)
	}

	plaintext, err := aead.Open(nil, nonceFor(counter), datagram[headerSize:], header)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	window.Mark(counter)
	return plaintext, nil
}

// replayWindowSize is how many trailing counters ReplayWindow remembers -
// generous enough to absorb any reordering UDP could plausibly deliver on
// a loopback or LAN path without being large enough to cost anything
// measurable to check.
const replayWindowSize = 64

// ReplayWindow rejects a datagram whose counter has already been marked
// seen, or has fallen too far behind the highest counter seen to be
// trustworthy - modeled directly on IPsec ESP/DTLS anti-replay, and
// correct under UDP's normal (bounded) reordering rather than assuming
// strict in-order delivery the way a stream transport would.
type ReplayWindow struct {
	mu      sync.Mutex
	started bool
	highest uint64
	mask    uint64 // bit i set means (highest - i) has been marked seen
}

// Seen reports whether counter has already been marked, or is too old to
// fit in the window, without mutating any state. Callers must call Mark
// after successfully authenticating a datagram whose counter Seen
// returned false for - see Open.
func (w *ReplayWindow) Seen(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch {
	case !w.started:
		return false
	case counter > w.highest:
		return false
	}

	age := w.highest - counter
	if age >= replayWindowSize {
		return true
	}

	return w.mask&(1<<age) != 0
}

// Mark records counter as seen, advancing the window (and forgetting
// whatever fell out the back of it) if counter is a new high-water mark.
func (w *ReplayWindow) Mark(counter uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		w.started = true
		w.highest = counter
		w.mask = 1
		return
	}

	if counter >= w.highest {
		shift := counter - w.highest
		if shift >= replayWindowSize {
			w.mask = 0
		} else {
			w.mask <<= shift
		}
		w.mask |= 1
		w.highest = counter
		return
	}

	if age := w.highest - counter; age < replayWindowSize {
		w.mask |= 1 << age
	}
}

// Session wraps one UDP data-plane connection with a send/receive AEAD
// key pair and a monotonic send counter - the per-hop encrypted-datagram
// transport share and listen each use for their one connection to
// relay's UDP data socket. relay itself doesn't use Session: it shares
// one socket across every session and calls Seal/Open directly, keyed by
// whichever route a packet's RoutingID names (see internal/relay/udp.go).
type Session struct {
	conn    net.Conn
	routing proto.RoutingID

	sendAEAD cipher.AEAD
	sendCtr  atomic.Uint64

	recvAEAD cipher.AEAD
	recv     ReplayWindow
}

// NewSession builds a Session over conn (already connected to its one
// peer, e.g. via [net.Dial]("udp", ...)), sealing outgoing datagrams with
// sendKey and opening incoming ones with recvKey.
func NewSession(conn net.Conn, routing proto.RoutingID, sendKey, recvKey [KeySize]byte) (*Session, error) {
	sendAEAD, err := NewAEAD(sendKey)
	if err != nil {
		return nil, err
	}

	recvAEAD, err := NewAEAD(recvKey)
	if err != nil {
		return nil, err
	}

	return &Session{conn: conn, routing: routing, sendAEAD: sendAEAD, recvAEAD: recvAEAD}, nil
}

// Send seals and writes plaintext as one datagram.
func (s *Session) Send(plaintext []byte) error {
	counter := s.sendCtr.Add(1) - 1
	if _, err := s.conn.Write(Seal(s.sendAEAD, s.routing, counter, plaintext)); err != nil {
		return fmt.Errorf("session send: %w", err)
	}

	return nil
}

// Recv reads, decrypts, and authenticates the next datagram into buf,
// silently retrying past any that fail authentication or the replay
// check - a misbehaving or malicious peer's traffic - rather than
// surfacing that as an error, since dropping a forged datagram and
// reading again is exactly how the caller was always going to have to
// handle a dropped or corrupted UDP packet.
func (s *Session) Recv(buf []byte) ([]byte, error) {
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("session recv: %w", err)
		}

		plaintext, err := Open(s.recvAEAD, &s.recv, buf[:n])
		if err != nil {
			continue
		}

		return plaintext, nil
	}
}
