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
const ALPN = "ggrok/1"

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

// Mode says whether a session forwards a TCP or a UDP service. The zero
// value is deliberately unused by either constant, so a zeroed Hello is
// never mistaken for a valid one.
type Mode uint8

const (
	// ModeTCP forwards a local TCP service, one QUIC stream per
	// connection.
	ModeTCP Mode = iota + 1

	// ModeUDP forwards a local UDP service, framed over QUIC datagrams.
	ModeUDP
)

// helloSize is the fixed wire size of a Hello: 1 byte Role + 1 byte Mode +
// 16 byte Token. Fixed width means no length prefix is needed.
const helloSize = 1 + 1 + tokenSize

// Hello is the first message a peer sends relay on the first stream it
// opens against a connection, identifying itself and which session it
// wants to publish or subscribe to.
type Hello struct {
	Role  Role
	Mode  Mode
	Token Token
}

// WriteHello writes h's fixed-width wire encoding to w in a single Write.
func WriteHello(w io.Writer, h Hello) error {
	if h.Role != RolePublish && h.Role != RoleSubscribe {
		return fmt.Errorf("write hello: invalid role %d", h.Role)
	}
	if h.Mode != ModeTCP && h.Mode != ModeUDP {
		return fmt.Errorf("write hello: invalid mode %d", h.Mode)
	}

	var buf [helloSize]byte
	buf[0] = byte(h.Role)
	buf[1] = byte(h.Mode)
	copy(buf[2:], h.Token[:])

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

	h := Hello{Role: Role(buf[0]), Mode: Mode(buf[1])}
	copy(h.Token[:], buf[2:])

	if h.Role != RolePublish && h.Role != RoleSubscribe {
		return Hello{}, fmt.Errorf("read hello: invalid role %d", h.Role)
	}
	if h.Mode != ModeTCP && h.Mode != ModeUDP {
		return Hello{}, fmt.Errorf("read hello: invalid mode %d", h.Mode)
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

// Handshake writes a Hello for role/mode/token on stream and waits for
// relay's ack, returning a descriptive error if relay rejected it. Shared
// by share (RolePublish) and listen (RoleSubscribe): both open a control
// stream and need the same send-Hello/await-ack handling before doing
// anything else on the connection.
func Handshake(stream io.ReadWriter, role Role, mode Mode, token Token) error {
	if err := WriteHello(stream, Hello{Role: role, Mode: mode, Token: token}); err != nil {
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

// subscriberFrameHeaderSize and publisherFrameHeaderSize are the datagram
// header widths on the listen<->relay and relay<->share legs respectively.
const (
	subscriberFrameHeaderSize = 2
	publisherFrameHeaderSize  = 4
)

// EncodeSubscriberFrame frames a UDP-mode datagram for the listen<->relay
// leg, tagging it with the FlowID of the local client it came from (or is
// destined for).
func EncodeSubscriberFrame(flow FlowID, payload []byte) []byte {
	frame := make([]byte, subscriberFrameHeaderSize+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(flow))
	copy(frame[subscriberFrameHeaderSize:], payload)
	return frame
}

// DecodeSubscriberFrame reverses EncodeSubscriberFrame. The returned
// payload aliases frame.
func DecodeSubscriberFrame(frame []byte) (FlowID, []byte, error) {
	if len(frame) < subscriberFrameHeaderSize {
		return 0, nil, fmt.Errorf("decode subscriber frame: short frame (%d bytes)", len(frame))
	}

	flow := FlowID(binary.BigEndian.Uint16(frame))
	return flow, frame[subscriberFrameHeaderSize:], nil
}

// EncodePublisherFrame frames a UDP-mode datagram for the relay<->share
// leg, tagging it with which subscriber's which local client it came from
// (or is destined for) - necessary once more than one subscriber's traffic
// shares the one publisher connection.
func EncodePublisherFrame(sub SubscriberID, flow FlowID, payload []byte) []byte {
	frame := make([]byte, publisherFrameHeaderSize+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(sub))
	binary.BigEndian.PutUint16(frame[2:], uint16(flow))
	copy(frame[publisherFrameHeaderSize:], payload)
	return frame
}

// DecodePublisherFrame reverses EncodePublisherFrame. The returned payload
// aliases frame.
func DecodePublisherFrame(frame []byte) (SubscriberID, FlowID, []byte, error) {
	if len(frame) < publisherFrameHeaderSize {
		return 0, 0, nil, fmt.Errorf("decode publisher frame: short frame (%d bytes)", len(frame))
	}

	sub := SubscriberID(binary.BigEndian.Uint16(frame))
	flow := FlowID(binary.BigEndian.Uint16(frame[2:]))
	return sub, flow, frame[publisherFrameHeaderSize:], nil
}
