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

	// ConnData marks a connection carrying an Attach message and then
	// raw forwarded bytes for exactly one logical TCP-mode stream.
	ConnData
)

// WriteConnKind writes kind to w in a single Write.
func WriteConnKind(w io.Writer, kind ConnKind) error {
	if kind != ConnControl && kind != ConnData {
		return fmt.Errorf("write conn kind: invalid kind %d", kind)
	}

	if _, err := w.Write([]byte{byte(kind)}); err != nil {
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
	if kind != ConnControl && kind != ConnData {
		return 0, fmt.Errorf("read conn kind: invalid kind %d", kind)
	}

	return kind, nil
}
