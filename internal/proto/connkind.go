package proto

import (
	"fmt"
	"io"
)

// ConnKind is the first byte written on every TCP connection a peer opens
// to relay, before anything else - it lets relay tell a session's one
// control connection apart from the many short-lived data connections
// TCP-mode opens per forwarded local connection, since Hello and Attach
// would otherwise both look like "some small enum in the first byte" with
// no way to tell which is which.
type ConnKind uint8

const (
	// ConnControl marks a connection carrying a Hello handshake and,
	// afterward, ControlType frames for the life of a session.
	ConnControl ConnKind = iota + 1

	// ConnData marks a connection carrying an Attach message and then the
	// sealed bytes of exactly one forwarded stream.
	ConnData

	// ConnAdmin marks a connection from an operator's admin client: it
	// carries an AdminHello and then admin frames for as long as the
	// operator keeps it open. Unlike ConnControl and ConnData it belongs to
	// no session - it is about relay itself.
	//
	// Adding this value did not bump ALPN, deliberately. The pin exists so
	// that peers which disagree about what a byte means refuse each other,
	// and an older relay reading this kind fails in ReadConnKind with
	// "invalid kind 3" and closes - a clean refusal, which is the outcome
	// the pin is there to guarantee. No existing byte changed meaning.
	ConnAdmin
)

// validConnKind reports whether kind is one this build knows. Both directions
// check it, so a garbled or newer byte is refused at the edge rather than
// dispatched on.
func validConnKind(kind ConnKind) bool {
	return kind == ConnControl || kind == ConnData || kind == ConnAdmin
}

// WriteConnKind writes kind to w in a single Write.
func WriteConnKind(w io.Writer, kind ConnKind) error {
	if !validConnKind(kind) {
		return fmt.Errorf("write conn kind: invalid kind %d", kind)
	}

	if err := writeFull(w, []byte{byte(kind)}); err != nil {
		return fmt.Errorf("write conn kind: %w", err)
	}

	return nil
}

// ReadConnKind reads a kind byte previously written by WriteConnKind.
func ReadConnKind(r io.Reader) (ConnKind, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, fmt.Errorf("read conn kind: %w", err)
	}

	kind := ConnKind(buf[0])
	if !validConnKind(kind) {
		return 0, fmt.Errorf("read conn kind: invalid kind %d", kind)
	}

	return kind, nil
}
