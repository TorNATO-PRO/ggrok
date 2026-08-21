package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ALPN is the protocol identifier both ends of every TLS connection in
// ggrok negotiate (see internal/mtls.LoadConfig's NextProtos), so a peer
// speaking some other protocol on the same port can't be mistaken for a
// ggrok node.
//
// Bumped to ggrok/3 when port ranges widened the datagram header again,
// to six bytes, to carry the PortIndex a frame belongs to (see
// FrameHeaderSize), and widened Hello and Attach to match. Every past bump
// has had the same character: a peer speaking the older version frames its
// datagrams differently, so a newer peer parses the header at the wrong
// offsets and reads a different subscriber, flow and port entirely -
// traffic silently delivered to the wrong local client rather than an
// error. The version is part of the ALPN so that mismatch is refused
// during the handshake instead of being discovered as misrouted packets.
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

// Mode says whether a session forwards a TCP service.
// The zero value is deliberately unused, so a zeroed Hello is never mistaken
// for a valid one.
type Mode uint8

const (
	// ModeTCP forwards a local TCP service, one QUIC stream per connection.
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
// 2 byte Ports + 16 byte Token. Fixed width means no length prefix is needed.
const helloSize = 1 + 1 + 2 + tokenSize

// helloPortsOffset locates the Ports field, which comes after the mode.
const helloPortsOffset = 2

// Hello is the first message a peer sends relay on the first stream it
// opens against a connection, identifying itself and which session it
// wants to publish or subscribe to.
type Hello struct {
	Role  Role
	Mode  Mode
	Token Token

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

	var buf [helloSize]byte
	buf[0] = byte(h.Role)
	buf[1] = byte(h.Mode)
	binary.BigEndian.PutUint16(buf[helloPortsOffset:], h.Ports)
	copy(buf[helloPortsOffset+2:], h.Token[:])

	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}

	return nil
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
	copy(h.Token[:], buf[helloPortsOffset+2:])

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

	// AckNoSuchSession means a subscriber's token has no active
	// publisher.
	AckNoSuchSession

	// AckModeMismatch means a subscriber's mode doesn't match the
	// session's publisher.
	AckModeMismatch

	// AckPublisherExists means a publisher's token already has an
	// active publisher.
	AckPublisherExists

	// AckPortsMismatch means a subscriber's port count doesn't match the
	// session's publisher - see Hello.Ports.
	AckPortsMismatch
)

// Err returns nil for AckOK, and a descriptive error for every rejection
// status.
func (s AckStatus) Err() error {
	switch s {
	case AckOK:
		return nil
	case AckNoSuchSession:
		return errors.New("no active session for this token")
	case AckModeMismatch:
		return errors.New("mode does not match this session's publisher")
	case AckPublisherExists:
		return errors.New("this token already has an active publisher")
	case AckPortsMismatch:
		return errors.New("port count does not match this session's publisher")
	default:
		return fmt.Errorf("unknown ack status %d", s)
	}
}

// WriteAck writes status to w in a single Write.
func WriteAck(w io.Writer, status AckStatus) error {
	if _, err := w.Write([]byte{byte(status)}); err != nil {
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

// Handshake writes a Hello for role/mode/ports/token on stream and waits
// for relay's ack, returning a descriptive error if relay rejected it.
// Shared by share (RolePublish) and listen (RoleSubscribe): both open a
// control stream and need the same send-Hello/await-ack handling before
// doing anything else on the connection.
func Handshake(stream io.ReadWriter, role Role, mode Mode, ports uint16, token Token) error {
	if err := WriteHello(stream, Hello{Role: role, Mode: mode, Ports: ports, Token: token}); err != nil {
		return err
	}

	status, err := ReadAck(stream)
	if err != nil {
		return err
	}

	return status.Err()
}

// SubscriberID identifies one listen connection within a session, assigned
// by relay when it bridges a subscriber.
type SubscriberID uint16

// FlowID identifies one local UDP client within a subscriber's own
// connection, assigned by listen. Together with SubscriberID it
// disambiguates every local UDP client of every subscriber sharing one
// publisher connection.
type FlowID uint16

// PortIndex names one port by its offset within a session's range rather
// than by number - index 0 is the first port share forwards and the first
// port listen binds, index 1 the next, and so on. The two sides need not
// use the same port numbers (see hostport.Range), and relay is told
// nothing about either side's numbers, so the index is the only thing
// that means anything on the wire.
type PortIndex uint16
