package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ALPN is the protocol identifier both ends of every TLS connection in ggrok
// negotiate (see internal/mtls.LoadConfig's NextProtos), so a peer speaking
// some other protocol on the same port can't be mistaken for a ggrok node.
//
// The version has to change whenever the meaning of bytes on the wire does,
// even when their layout is unchanged. Every message here is fixed-width with
// no self-description, so peers that disagree about what a field means still
// parse each other's messages successfully and act on the wrong values - a
// failure that surfaces as traffic going somewhere it shouldn't rather than
// as an error. Negotiating the version in the handshake turns that into a
// clean refusal to connect.
//
// Purely additive changes do not bump it, because they cannot produce that
// failure. A new ConnKind value (see ConnAdmin) is the worked example: an
// older peer reading it fails in ReadConnKind and closes, which is already
// the clean refusal this pin exists to produce. What forces a bump is an
// existing byte meaning something new, or a handshake growing a round-trip.
//
// The current version covers: TCP-only sessions, Hello and Attach naming a
// session by a SessionID derived from the publisher's session public key, a
// publish handshake in which relay challenges the claimant to sign for that
// key (see VerifyPublishClaim), and a data plane authenticated against fresh
// challenges and its port before any local service is opened (see
// NewAuthenticatedConn).
const ALPN = "ggrok/3"

// Role says which end of a session a connection belongs to. The zero value
// is deliberately unused by either constant, so a zeroed Hello is never
// mistaken for a valid one.
type Role uint8

const (
	// RolePublish marks a share connection: it owns the local service
	// being forwarded.
	RolePublish Role = iota + 1

	// RoleSubscribe marks a listen connection: it wants to be bridged
	// to a publisher's session.
	RoleSubscribe
)

// Mode says what kind of service a session forwards. There is only one today,
// but both ends still declare it and relay still checks that a subscriber
// matches its publisher, so adding a second kind cannot silently pair two
// peers that disagree. The zero value is deliberately unused, so a zeroed
// Hello is never mistaken for a valid one.
type Mode uint8

const (
	// ModeTCP forwards a local TCP service, one data connection to relay per
	// forwarded connection.
	ModeTCP Mode = iota + 1
)

// String names a mode for logs and error messages, where the raw number
// says nothing to anyone reading them.
func (m Mode) String() string {
	switch m {
	case ModeTCP:
		return "tcp"
	default:
		return fmt.Sprintf("invalid mode (%d)", uint8(m))
	}
}

// helloSize is the fixed wire size of a Hello: 1 byte Role + 1 byte Mode +
// 2 byte Ports + 16 byte SessionID. Fixed width means no length prefix is
// needed. helloSessionOffset locates the SessionID behind the port count.
const (
	roleByteSize       = 1
	modeByteSize       = 1
	portsByteSize      = 2
	helloSize          = roleByteSize + modeByteSize + portsByteSize + SessionIDSize
	helloPortsOffset   = 2
	helloSessionOffset = helloPortsOffset + 2
)

// Hello is the first message a peer sends relay on a control connection,
// identifying itself and which session it wants to publish or subscribe to.
type Hello struct {
	Role      Role
	Mode      Mode
	SessionID SessionID

	// Ports is how many consecutive ports this peer forwards (publish) or
	// binds (subscribe) - see hostport.Range. Both ends of a session must
	// agree on the count, since everything downstream addresses a port by
	// its index within the range rather than by number; relay is what
	// enforces that, rejecting a mismatched subscriber with
	// AckPortsMismatch instead of letting it discover the problem as
	// connections that quietly fail on some ports and not others.
	Ports uint16
}

// WriteHello writes h's fixed-width wire encoding to w in a single Write.
func WriteHello(w io.Writer, h Hello) error {
	if h.Role != RolePublish && h.Role != RoleSubscribe {
		return fmt.Errorf("write hello: invalid role %d", h.Role)
	}
	if h.Mode != ModeTCP {
		return fmt.Errorf("write hello: invalid mode %d", h.Mode)
	}
	if h.Ports == 0 {
		return fmt.Errorf("write hello: port count must be at least 1")
	}

	buf := encodeHello(h)
	if err := writeFull(w, buf[:]); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}

	return nil
}

// encodeHello renders h's fixed-width wire encoding. It is shared with
// publishClaim, so what a publisher signs is byte-for-byte what relay read -
// re-deriving the bytes on either side would risk the two drifting apart the
// next time a field is added.
func encodeHello(h Hello) [helloSize]byte {
	var buf [helloSize]byte
	buf[0] = byte(h.Role)
	buf[1] = byte(h.Mode)
	binary.BigEndian.PutUint16(buf[helloPortsOffset:], h.Ports)
	copy(buf[helloSessionOffset:], h.SessionID[:])
	return buf
}

// ReadHello reads and validates a Hello previously written by WriteHello.
func ReadHello(r io.Reader) (Hello, error) {
	var buf [helloSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Hello{}, fmt.Errorf("read hello: %w", err)
	}

	h := Hello{
		Role:  Role(buf[0]),
		Mode:  Mode(buf[1]),
		Ports: binary.BigEndian.Uint16(buf[helloPortsOffset:]),
	}
	copy(h.SessionID[:], buf[helloSessionOffset:])

	if h.Role != RolePublish && h.Role != RoleSubscribe {
		return Hello{}, fmt.Errorf("read hello: invalid role %d", h.Role)
	}
	if h.Mode != ModeTCP {
		return Hello{}, fmt.Errorf("read hello: invalid mode %d", h.Mode)
	}
	if h.Ports == 0 {
		return Hello{}, fmt.Errorf("read hello: port count must be at least 1")
	}

	return h, nil
}

// AckStatus is relay's one-byte response to a Hello, so share/listen fail
// fast with a clear reason instead of hanging or discovering the problem
// only once real traffic fails to flow.
type AckStatus uint8

const (
	// AckOK means the Hello was accepted; the connection is now
	// registered (publish) or bridged (subscribe).
	AckOK AckStatus = iota

	// AckNoSuchSession means a subscriber's SessionID has no active
	// publisher.
	AckNoSuchSession

	// AckModeMismatch means a subscriber's mode doesn't match the
	// session's publisher.
	AckModeMismatch

	// AckPublisherExists means a publisher's SessionID already has an
	// active publisher.
	AckPublisherExists

	// AckPortsMismatch means a subscriber's port count doesn't match the
	// session's publisher - see Hello.Ports.
	AckPortsMismatch

	// AckDenied means relay refused this peer outright rather than because
	// of a timing or configuration mismatch: a publisher that could not
	// prove the session is its own (see VerifyPublishClaim) is the only
	// thing that earns it today.
	AckDenied
)

// The errors [AckStatus.Err] reports, one per rejection status. They're
// sentinels rather than fresh errors so a caller can tell the transient
// rejections apart from the permanent ones: a peer that arrives before its
// counterpart, or one whose predecessor relay hasn't timed out yet, is
// turned away with ErrNoSuchSession or ErrPublisherExists and should try
// again, where a mode or port-count disagreement means the two peers were
// started with incompatible arguments and no amount of retrying settles it.
// ErrDenied is terminal in the same way for a different reason: relay
// refused this peer for who it is, and another attempt is the same peer.
var (
	ErrNoSuchSession   = errors.New("no active session for this token")
	ErrModeMismatch    = errors.New("mode does not match this session's publisher")
	ErrPublisherExists = errors.New("this session already has an active publisher")
	ErrPortsMismatch   = errors.New("port count does not match this session's publisher")
	ErrDenied          = errors.New("relay denied this peer")
)

// Err returns nil for AckOK, and the matching sentinel for every rejection
// status.
func (s AckStatus) Err() error {
	switch s {
	case AckOK:
		return nil
	case AckNoSuchSession:
		return ErrNoSuchSession
	case AckModeMismatch:
		return ErrModeMismatch
	case AckPublisherExists:
		return ErrPublisherExists
	case AckPortsMismatch:
		return ErrPortsMismatch
	case AckDenied:
		return ErrDenied
	default:
		return fmt.Errorf("unknown ack status %d", s)
	}
}

// WriteAck writes status to w in a single Write.
func WriteAck(w io.Writer, status AckStatus) error {
	if err := writeFull(w, []byte{byte(status)}); err != nil {
		return fmt.Errorf("write ack: %w", err)
	}

	return nil
}

// ReadAck reads a status byte previously written by WriteAck. The returned
// error is only non-nil on an I/O failure - a rejection status is returned
// successfully and the caller should check status.Err().
func ReadAck(r io.Reader) (AckStatus, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, fmt.Errorf("read ack: %w", err)
	}

	return AckStatus(buf[0]), nil
}

// Handshake writes a Hello for role/mode/ports on stream and waits for
// relay's ack, returning a descriptive error if relay rejected it. Shared by
// share (RolePublish) and listen (RoleSubscribe): both open a control stream
// and need the same send-Hello/await-ack handling before doing anything else
// on the connection.
//
// A publisher answers relay's challenge in between, since the SessionID names
// a session without proving any right to it - every subscriber can derive the
// same value. Nothing a subscriber can produce passes that step, which is
// what keeps one from taking the publisher slot the moment the real
// publisher's connection drops.
//
// No secret in creds reaches the wire: what identifies the session to relay
// is the SessionID, which is enough to route by and not enough to decrypt
// with, and what claims it is a signature rather than the key that made it.
func Handshake(stream io.ReadWriter, role Role, mode Mode, ports uint16, creds Credentials) error {
	hello := Hello{Role: role, Mode: mode, Ports: ports, SessionID: creds.SessionID()}
	if err := WriteHello(stream, hello); err != nil {
		return err
	}

	if role == RolePublish {
		if err := provePublisher(stream, creds, hello); err != nil {
			return err
		}
	}

	status, err := ReadAck(stream)
	if err != nil {
		return err
	}

	return status.Err()
}

// SubscriberID identifies one listen connection within a session, assigned by
// relay when it bridges a subscriber. It is relay's own bookkeeping - it
// never reaches either peer.
type SubscriberID uint64

// PortIndex names one port by its offset within a session's range rather
// than by number - index 0 is the first port share forwards and the first
// port listen binds, index 1 the next, and so on. The two sides need not
// use the same port numbers (see hostport.Range), and relay is told
// nothing about either side's numbers, so the index is the only thing
// that means anything on the wire.
type PortIndex uint16
