package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// AdminType identifies an admin frame. Admin frames travel only on a
// ConnAdmin connection, never on ConnControl or ConnData.
type AdminType uint8

const (
	// AdminHello is the first frame an admin client sends: a version probe
	// relay answers with AdminAck before accepting anything else.
	AdminHello AdminType = iota + 1

	// AdminAck is relay's answer to AdminHello. A client whose certificate
	// does not carry the admin role gets one with Err set, rather than a
	// bare close, so the operator learns why.
	AdminAck

	// AdminList asks for one Snapshot of everything relay is currently
	// carrying.
	AdminList

	// AdminSnapshot carries the answer to AdminList.
	AdminSnapshot

	// AdminKick asks relay to drop every live connection belonging to one
	// certificate serial.
	AdminKick

	// AdminReloadCRL asks relay to re-read its revoked-serial file and then
	// kick whatever the new list covers.
	AdminReloadCRL

	// AdminResult carries the outcome of a mutating request.
	AdminResult
)

// String renders typ for logs and errors. The default arm matters: an admin
// client and a relay may be different builds, and an unknown type has to be
// reportable rather than rendered as a bare number with no context.
func (t AdminType) String() string {
	switch t {
	case AdminHello:
		return "hello"
	case AdminAck:
		return "ack"
	case AdminList:
		return "list"
	case AdminSnapshot:
		return "snapshot"
	case AdminKick:
		return "kick"
	case AdminReloadCRL:
		return "reload-crl"
	case AdminResult:
		return "result"
	default:
		return fmt.Sprintf("AdminType(%d)", uint8(t))
	}
}

// AdminVersion is the admin protocol version this build speaks. It is
// separate from ALPN on purpose: the admin schema is JSON and self-
// describing, so it can grow fields without either side misreading the
// other, and a mismatch here is a negotiation rather than a refusal to
// connect.
const AdminVersion = 1

// adminHeaderSize is the frame header width: 1 byte AdminType + 4 byte
// big-endian payload length. Same shape as a control frame.
const adminHeaderSize = 1 + 4

// maxAdminPayload bounds an admin frame's payload. It is deliberately not
// maxControlPayload: that constant is a DoS bound on the data path, where
// every payload is a handful of bytes, and must not be relaxed because an
// unrelated plane needs room. A snapshot of a thousand sessions exceeds a
// kilobyte immediately, so admin frames get their own, larger bound.
const maxAdminPayload = 1 << 20

// AdminHelloPayload is a version probe.
type AdminHelloPayload struct {
	Version int `json:"v"`
}

// AdminAckPayload answers AdminHello. Err is empty when OK is true.
type AdminAckPayload struct {
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
	Version int    `json:"v"`
}

// AdminKickPayload names the certificate serial to drop, in the same text
// form ca crl writes and relay's revocation check compares, so a serial read
// off a snapshot can be used here unchanged.
type AdminKickPayload struct {
	Serial string `json:"serial"`
}

// AdminResultPayload is the outcome of a mutating request. Affected counts
// whatever the request acted on - connections closed, for a kick.
type AdminResultPayload struct {
	OK       bool   `json:"ok"`
	Detail   string `json:"detail,omitempty"`
	Affected int    `json:"affected"`
}

// Snapshot is everything relay is currently carrying, as of Now. Now is the
// client's clock reference: rates are the client's job to compute by diffing
// two snapshots, so relay keeps no rolling windows and no per-stream tickers
// whose only consumer would be a display.
type Snapshot struct {
	Now      time.Time        `json:"now"`
	Sessions []SessionSummary `json:"sessions"`
}

// SessionSummary is one publisher and everything attached to it.
type SessionSummary struct {
	// Tag is SessionID.LogTag(), never the whole SessionID. Six bytes is
	// by that method's own reasoning far too little to attach to a session
	// with, which is what lets an operator name a session out loud while
	// the identifier that would let someone join one stays off the wire.
	Tag         string           `json:"tag"`
	Mode        string           `json:"mode"`
	Ports       uint16           `json:"ports"`
	Since       time.Time        `json:"since"`
	Publisher   PeerSummary      `json:"publisher"`
	Subscribers []PeerSummary    `json:"subscribers"`
	Streams     []StreamSummary  `json:"streams"`
	Pending     []PendingSummary `json:"pending,omitempty"`
}

// PeerSummary is who is on one end of a connection. CN and Serial come from
// the certificate the CA vouched for, so they name a durable identity; Addr
// only says where the packets came from this time.
type PeerSummary struct {
	CN     string    `json:"cn"`
	Serial string    `json:"serial"`
	Addr   string    `json:"addr"`
	Since  time.Time `json:"since"`
}

// StreamSummary is one forwarded connection currently being spliced. The
// byte counts are monotonic totals for this stream, not rates; clients may
// derive a rate from the stream start time or from successive snapshots.
type StreamSummary struct {
	ReqID      uint64    `json:"req"`
	Port       uint16    `json:"port"`
	Started    time.Time `json:"started"`
	BytesToSub int64     `json:"bytes_to_subscriber"`
	BytesToPub int64     `json:"bytes_to_publisher"`
}

// PendingSummary is a subscriber data connection waiting on a publisher that
// has not fulfilled it yet. A tunnel that is stuck shows up here rather than
// in Streams, which is the distinction an operator is looking for.
type PendingSummary struct {
	ReqID   uint64    `json:"req"`
	Port    uint16    `json:"port"`
	Since   time.Time `json:"since"`
	Address string    `json:"addr"`
}

// WriteAdminFrame writes typ and payload to w as one length-prefixed frame,
// in a single Write. payload is marshalled as JSON; a nil payload writes an
// empty body.
//
// JSON here is a deliberate exception to this package's fixed-width
// discipline. That discipline exists because the data plane is hot,
// allocation-sensitive, and must never be ambiguous - none of which applies
// to admin traffic, which is low-frequency, human-facing, and has a schema
// that will grow. Self-description is precisely the property that lets it
// grow without the field-misreading hazard the ALPN comment describes.
func WriteAdminFrame(w io.Writer, typ AdminType, payload any) error {
	return writeAdminFrame(w, typ, payload, false)
}

// WriteAdminHello writes the connection discriminator and an AdminHello
// together. The bytes are identical to WriteConnKind(ConnAdmin) followed by
// WriteAdminFrame(AdminHello, ...), and it exists for the same reason
// WriteDataAttach does: the discriminator is not optional, and pairing it with
// the frame it introduces is what stops a caller from forgetting it.
//
// Forgetting it is not a loud failure. AdminHello's type byte is 1, which is
// also ConnControl, so a bare frame is dispatched as a control connection and
// then times out waiting for a Hello that will never come.
func WriteAdminHello(w io.Writer, payload AdminHelloPayload) error {
	return writeAdminFrame(w, AdminHello, payload, true)
}

func writeAdminFrame(w io.Writer, typ AdminType, payload any, withKind bool) error {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("write admin frame: marshal %s: %w", typ, err)
		}
	}

	if len(body) > maxAdminPayload {
		return fmt.Errorf("write admin frame: %s payload too large (%d bytes)", typ, len(body))
	}

	storage := make([]byte, 1+adminHeaderSize+len(body))
	buf := storage[1:]
	buf[0] = byte(typ)
	binary.BigEndian.PutUint32(buf[1:], uint32(len(body))) //nolint:gosec // bounded by maxAdminPayload above
	copy(buf[adminHeaderSize:], body)

	if withKind {
		storage[0] = byte(ConnAdmin)
		buf = storage
	}
	if err := writeFull(w, buf); err != nil {
		return fmt.Errorf("write admin frame: %w", err)
	}

	return nil
}

// ReadAdminFrame reads one frame previously written by WriteAdminFrame,
// returning its type and its raw JSON body. Decoding the body is the
// caller's job, since which type it decodes into depends on the frame type.
func ReadAdminFrame(r io.Reader) (AdminType, []byte, error) {
	var header [adminHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, fmt.Errorf("read admin frame: %w", err)
	}

	typ := AdminType(header[0])
	length := binary.BigEndian.Uint32(header[1:])
	if length > maxAdminPayload {
		return 0, nil, fmt.Errorf("read admin frame: %s payload too large (%d bytes)", typ, length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, fmt.Errorf("read admin frame: %w", err)
	}

	return typ, body, nil
}

// DecodeAdminPayload unmarshals an admin frame body into v. An empty body
// leaves v untouched, so a frame whose payload carries no information - an
// AdminList, say - needs no special case at the call site.
func DecodeAdminPayload(body []byte, v any) error {
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("decode admin payload: %w", err)
	}

	return nil
}
