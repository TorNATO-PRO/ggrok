package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// AttachKind says which side of a TCP-mode data connection a fresh Attach
// is coming from - relay handles the two very differently: a subscriber's
// attach is looking for a matching session to pair with; a publisher's
// attach is fulfilling a specific ControlRequestData relay already asked
// for.
type AttachKind uint8

const (
	// AttachSubscriber marks a data connection listen opened in response
	// to accepting a local connection - RequestID is unset.
	AttachSubscriber AttachKind = iota + 1

	// AttachPublisher marks a data connection share opened in response
	// to a ControlRequestData - RequestID identifies which one.
	AttachPublisher
)

// attachSize is the fixed wire size of an Attach: 1 byte Kind + 16 byte
// Token + 8 byte RequestID.
const attachSize = 1 + tokenSize + 8

// Attach is the first message a peer sends relay on a TCP-mode data
// connection, identifying which session it belongs to (and, for a
// publisher, which pending request it's fulfilling) before relay pairs it
// with its counterpart and starts splicing.
type Attach struct {
	Kind      AttachKind
	Token     Token
	RequestID uint64
}

// WriteAttach writes a's fixed-width wire encoding to w in a single Write.
func WriteAttach(w io.Writer, a Attach) error {
	if a.Kind != AttachSubscriber && a.Kind != AttachPublisher {
		return fmt.Errorf("write attach: invalid kind %d", a.Kind)
	}

	var buf [attachSize]byte
	buf[0] = byte(a.Kind)
	copy(buf[1:], a.Token[:])
	binary.BigEndian.PutUint64(buf[1+tokenSize:], a.RequestID)

	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write attach: %w", err)
	}

	return nil
}

// ReadAttach reads and validates an Attach previously written by
// WriteAttach.
func ReadAttach(r io.Reader) (Attach, error) {
	var buf [attachSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Attach{}, fmt.Errorf("read attach: %w", err)
	}

	a := Attach{Kind: AttachKind(buf[0])}
	copy(a.Token[:], buf[1:1+tokenSize])
	a.RequestID = binary.BigEndian.Uint64(buf[1+tokenSize:])

	if a.Kind != AttachSubscriber && a.Kind != AttachPublisher {
		return Attach{}, fmt.Errorf("read attach: invalid kind %d", a.Kind)
	}

	return a, nil
}
