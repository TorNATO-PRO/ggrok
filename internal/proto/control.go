package proto

import (
	"crypto/rand"
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
	// request - payload is the RequestID (8 bytes).
	ControlRequestData

	// ControlUDPSession is relay handing a peer the RoutingID for
	// UDP-mode's AEAD-encrypted data plane - payload is the RoutingID
	// (8 bytes).
	ControlUDPSession
)

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
// single big-endian uint64 RequestID.
const requestDataSize = 8

// WriteRequestData writes a ControlRequestData frame for id.
func WriteRequestData(w io.Writer, id uint64) error {
	var payload [requestDataSize]byte
	binary.BigEndian.PutUint64(payload[:], id)
	return WriteControlFrame(w, ControlRequestData, payload[:])
}

// ReadRequestData decodes a ControlRequestData frame's payload.
func ReadRequestData(payload []byte) (uint64, error) {
	if len(payload) != requestDataSize {
		return 0, fmt.Errorf("read request data: want %d bytes, got %d", requestDataSize, len(payload))
	}

	return binary.BigEndian.Uint64(payload), nil
}

// routingIDSize is the width of a RoutingID in bytes.
const routingIDSize = 8

// RoutingID is an opaque, per-UDP-session identifier relay mints at
// registration and hands back to both peers over their (encrypted)
// control connections. Unlike Token, a RoutingID travels in cleartext on
// every raw UDP data-plane packet so relay can demux which session's AEAD
// key to try before it can decrypt anything - it's deliberately not the
// Token itself (which today never appears in cleartext on the wire) and
// grants nothing on its own without the session's separately-derived AEAD
// key.
type RoutingID [routingIDSize]byte

// NewRoutingID draws a fresh, cryptographically random routing ID.
func NewRoutingID() (RoutingID, error) {
	var id RoutingID
	if _, err := rand.Read(id[:]); err != nil {
		return RoutingID{}, fmt.Errorf("generate routing id: %w", err)
	}

	return id, nil
}

// WriteUDPSession writes a ControlUDPSession frame for id.
func WriteUDPSession(w io.Writer, id RoutingID) error {
	return WriteControlFrame(w, ControlUDPSession, id[:])
}

// ReadUDPSession decodes a ControlUDPSession frame's payload.
func ReadUDPSession(payload []byte) (RoutingID, error) {
	if len(payload) != routingIDSize {
		return RoutingID{}, fmt.Errorf("read udp session: want %d bytes, got %d", routingIDSize, len(payload))
	}

	var id RoutingID
	copy(id[:], payload)
	return id, nil
}
