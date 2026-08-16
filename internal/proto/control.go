package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ControlType tags a frame sent on a session's control connection after
// the initial Hello handshake. Unlike Hello/Attach's fixed-width
// messages, control frames carry a length prefix since their payloads
// vary in size (or are empty, for Ping/Pong).
type ControlType uint8

const (
	// ControlPing and ControlPong are an empty-payload liveness
	// heartbeat, exchanged periodically so either side notices a
	// hung-but-open peer that TCP keepalive alone would miss.
	ControlPing ControlType = iota + 1
	ControlPong

	// ControlRequestData is relay asking a publisher to open a new
	// TCP-mode data connection for a specific pending subscriber
	// request - payload is the RequestID (8 bytes) followed by the
	// PortIndex the subscriber accepted that connection on (2 bytes),
	// which is what tells the publisher which of its local ports to dial.
	ControlRequestData

	// ControlSubscriberID is relay handing a UDP-mode subscriber the
	// SubscriberID it assigned - payload is the SubscriberID (2 bytes).
	// The subscriber presents this same ID in its UDPAttach handshake when
	// it dials relay's QUIC data connection, so relay can tell which
	// already-registered subscriber that datagram-only connection belongs
	// to (a session can have many concurrent subscribers, and the QUIC
	// connection carries no other identifying information beyond the
	// token, which every subscriber shares).
	ControlSubscriberID

	// ControlSessionClosed is relay telling a subscriber that the session
	// it is attached to has ended - payload is a single
	// SessionCloseReason byte. Nothing else on the wire carries that news:
	// a subscriber whose publisher has gone away still holds a perfectly
	// healthy control connection to relay, so without this frame it goes
	// on heartbeating and binding its local port, indistinguishable from
	// an idle-but-working tunnel, until someone notices traffic vanishing.
	ControlSessionClosed
)

// SessionCloseReason says why a session ended. It travels as the
// single-byte payload of a ControlSessionClosed frame; a receiver that
// doesn't recognize the value should still treat the session as over,
// since the frame type alone is the verdict and the reason is only
// explanation.
type SessionCloseReason uint8

const (
	// ReasonPublisherGone means the session's publisher (share)
	// disconnected, leaving nothing on the other end to forward to.
	ReasonPublisherGone SessionCloseReason = iota + 1
)

// String renders a reason for a human - including ones this build
// doesn't know, which a newer relay may send.
func (r SessionCloseReason) String() string {
	switch r {
	case ReasonPublisherGone:
		return "publisher disconnected"
	default:
		return fmt.Sprintf("unspecified reason (%d)", uint8(r))
	}
}

// sessionClosedSize is the width of a ControlSessionClosed frame's
// payload: a single SessionCloseReason byte.
const sessionClosedSize = 1

// WriteSessionClosed writes a ControlSessionClosed frame for reason.
func WriteSessionClosed(w io.Writer, reason SessionCloseReason) error {
	return WriteControlFrame(w, ControlSessionClosed, []byte{byte(reason)})
}

// ReadSessionClosed decodes a ControlSessionClosed frame's payload.
func ReadSessionClosed(payload []byte) (SessionCloseReason, error) {
	if len(payload) != sessionClosedSize {
		return 0, fmt.Errorf("read session closed: want %d byte, got %d", sessionClosedSize, len(payload))
	}

	return SessionCloseReason(payload[0]), nil
}

// controlHeaderSize is the frame header width: 1 byte ControlType + 4
// byte big-endian payload length.
const controlHeaderSize = 1 + 4

// maxControlPayload bounds a control frame's payload so a corrupt or
// malicious length prefix can't make ReadControlFrame allocate or block
// reading an unbounded amount of data. Every payload this package defines
// today is 8 bytes; this leaves generous headroom without being
// unbounded.
const maxControlPayload = 1024

// WriteControlFrame writes typ and payload to w as one length-prefixed
// frame, in a single Write.
func WriteControlFrame(w io.Writer, typ ControlType, payload []byte) error {
	if len(payload) > maxControlPayload {
		return fmt.Errorf("write control frame: payload too large (%d bytes)", len(payload))
	}

	buf := make([]byte, controlHeaderSize+len(payload))
	buf[0] = byte(typ)
	binary.BigEndian.PutUint32(buf[1:], uint32(len(payload))) //nolint:gosec // bounded by maxControlPayload above
	copy(buf[controlHeaderSize:], payload)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write control frame: %w", err)
	}

	return nil
}

// ReadControlFrame reads one frame previously written by
// WriteControlFrame.
func ReadControlFrame(r io.Reader) (ControlType, []byte, error) {
	var header [controlHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, fmt.Errorf("read control frame: %w", err)
	}

	typ := ControlType(header[0])
	length := binary.BigEndian.Uint32(header[1:])
	if length > maxControlPayload {
		return 0, nil, fmt.Errorf("read control frame: payload too large (%d bytes)", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read control frame: %w", err)
	}

	return typ, payload, nil
}

// requestDataSize is the width of a ControlRequestData frame's payload: a
// big-endian uint64 RequestID followed by a big-endian PortIndex.
const (
	requestDataSize    = 8 + 2
	requestDataPortOff = 8
)

// WriteRequestData writes a ControlRequestData frame for id, naming the
// port of the session's range the connection was accepted on.
func WriteRequestData(w io.Writer, id uint64, port PortIndex) error {
	var payload [requestDataSize]byte
	binary.BigEndian.PutUint64(payload[:], id)
	binary.BigEndian.PutUint16(payload[requestDataPortOff:], uint16(port))

	return WriteControlFrame(w, ControlRequestData, payload[:])
}

// ReadRequestData decodes a ControlRequestData frame's payload.
func ReadRequestData(payload []byte) (uint64, PortIndex, error) {
	if len(payload) != requestDataSize {
		return 0, 0, fmt.Errorf("read request data: want %d bytes, got %d", requestDataSize, len(payload))
	}

	id := binary.BigEndian.Uint64(payload)
	port := PortIndex(binary.BigEndian.Uint16(payload[requestDataPortOff:]))

	return id, port, nil
}

// subscriberIDSize is the width of a ControlSubscriberID frame's payload:
// a single big-endian SubscriberID.
const subscriberIDSize = 2

// WriteSubscriberID writes a ControlSubscriberID frame for id.
func WriteSubscriberID(w io.Writer, id SubscriberID) error {
	var payload [subscriberIDSize]byte
	binary.BigEndian.PutUint16(payload[:], uint16(id))
	return WriteControlFrame(w, ControlSubscriberID, payload[:])
}

// ReadSubscriberID decodes a ControlSubscriberID frame's payload.
func ReadSubscriberID(payload []byte) (SubscriberID, error) {
	if len(payload) != subscriberIDSize {
		return 0, fmt.Errorf("read subscriber id: want %d bytes, got %d", subscriberIDSize, len(payload))
	}

	return SubscriberID(binary.BigEndian.Uint16(payload)), nil
}
