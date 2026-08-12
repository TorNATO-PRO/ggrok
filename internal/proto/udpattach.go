package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// udpAttachSize is the fixed wire size of a UDPAttach: 1 byte Role + 16
// byte Token + 2 byte SubscriberID.
const udpAttachSize = 1 + tokenSize + 2

// UDPAttach is the first (and only) message a peer sends relay on a
// UDP-mode data connection's first stream, before that connection settles
// into carrying nothing but datagrams. Unlike TCP-mode's data connections,
// this one is dialed once and held open for the life of the session, so
// there's no RequestID to fulfill - only enough identity for relay to pair
// it with the session (and, for a subscriber, the specific already-
// registered subscriber slot) that its control connection set up first.
//
// SubscriberID is meaningful only when Role is RoleSubscribe: it's the ID
// relay assigned over the control connection via a ControlSubscriberID
// frame (see internal/relay's registry.go), presented back here since a
// session can have many concurrent subscribers and the token alone
// doesn't say which one this connection is for. A publisher needs no such
// disambiguation - a session has exactly one - so it's left zero.
type UDPAttach struct {
	Role         Role
	Token        Token
	SubscriberID SubscriberID
}

// WriteUDPAttach writes a's fixed-width wire encoding to w in a single
// Write.
func WriteUDPAttach(w io.Writer, a UDPAttach) error {
	if a.Role != RolePublish && a.Role != RoleSubscribe {
		return fmt.Errorf("write udp attach: invalid role %d", a.Role)
	}

	var buf [udpAttachSize]byte
	buf[0] = byte(a.Role)
	copy(buf[1:], a.Token[:])
	binary.BigEndian.PutUint16(buf[1+tokenSize:], uint16(a.SubscriberID))

	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write udp attach: %w", err)
	}

	return nil
}

// ReadUDPAttach reads and validates a UDPAttach previously written by
// WriteUDPAttach.
func ReadUDPAttach(r io.Reader) (UDPAttach, error) {
	var buf [udpAttachSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return UDPAttach{}, fmt.Errorf("read udp attach: %w", err)
	}

	a := UDPAttach{Role: Role(buf[0])}
	copy(a.Token[:], buf[1:1+tokenSize])
	a.SubscriberID = SubscriberID(binary.BigEndian.Uint16(buf[1+tokenSize:]))

	if a.Role != RolePublish && a.Role != RoleSubscribe {
		return UDPAttach{}, fmt.Errorf("read udp attach: invalid role %d", a.Role)
	}

	return a, nil
}
