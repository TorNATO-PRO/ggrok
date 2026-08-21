// Package hostport provides a parsed and validated type indicating that we
// do indeed have a valid DNS name, IPv4, IPv6 address and port pairing. This
// will help make callsites cleaner down the line.
package hostport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Kind is the kind of the HostPort, the variants of which
// are enumerated below.
type Kind uint8

const (
	// KindIP is the kind when a HostPort is a resolved IP address.
	KindIP Kind = iota

	// KindName is when the HostPort is a DNS name.
	KindName
)

// HostPort is host:port where host is either a resolved IP or a DNS name.
type HostPort struct {
	// kind is the kind of the HostPort
	kind Kind

	// ip is the IP address, if of course the host:port pair uses an IP address.
	ip netip.Addr

	// name is a DNS name, if the host:port pair uses a DNS name.
	name string

	// port is the port that we are listening on.
	port uint16
}

// ErrInvalidHostPort is the error you get when your host:port pair is invalid.
var ErrInvalidHostPort = errors.New("hostport: invalid host:port")

// Parse takes a string an attempts to extract a host:port pair.
func Parse(s string) (HostPort, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return HostPort{}, fmt.Errorf("%w: %w", ErrInvalidHostPort, err)
	}

	port, err := parsePort(portStr)
	if err != nil {
		return HostPort{}, err
	}

	return newHostPort(host, port)
}

// parsePort parses one port number.
func parsePort(s string) (uint16, error) {
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: bad port: %w", ErrInvalidHostPort, err)
	}

	return uint16(port), nil
}

// newHostPort pairs an already-parsed port with a host, deciding which
// kind of host it is.
func newHostPort(host string, port uint16) (HostPort, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return HostPort{kind: KindIP, ip: ip, port: port}, nil
	}

	if host == "" || strings.ContainsAny(host, " \t") {
		return HostPort{}, fmt.Errorf("%w: bad host %q", ErrInvalidHostPort, host)
	}

	return HostPort{kind: KindName, name: host, port: port}, nil
}

// IsIP returns true when the host:port pair is an IP.
func (h HostPort) IsIP() bool {
	return h.kind == KindIP
}

// IsName returns true when the host:port pair is a DNS name.
func (h HostPort) IsName() bool {
	return h.kind == KindName
}

// Match defines a pattern matching function over the HostPort pair.
func (h HostPort) Match(onIP func(netip.Addr, uint16) any, onName func(string, uint16) any) any {
	if h.kind == KindIP {
		return onIP(h.ip, h.port)
	}

	return onName(h.name, h.port)
}

// String obtains the underlying string from this type.
func (h HostPort) String() string {
	if h.kind == KindIP {
		return net.JoinHostPort(h.ip.String(), strconv.Itoa(int(h.port)))
	}
	return net.JoinHostPort(h.name, strconv.Itoa(int(h.port)))
}

// UnmarshalText makes this a drop-in scalar type.
func (h *HostPort) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}

	*h = parsed
	return nil
}

// MarshalText makes this a drop-in scalar type.
func (h HostPort) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// MaxPorts bounds how many ports one Range may span. A share or listen
// holds a live socket per port in its range for the whole session, so the
// span is a direct multiplier on file descriptors and - for listen's UDP
// mode - on socket buffer memory, which is sized generously per socket
// (see listen's udpSocketBufferSize). A thousand is far past any plausible
// service and still nowhere near a default fd limit.
const MaxPorts = 1024

// ErrInvalidRange is the error you get when your host:port range is
// invalid. It's distinct from ErrInvalidHostPort because a range has
// failure modes a single pair doesn't - an inverted or oversized span.
var ErrInvalidRange = errors.New("hostport: invalid port range")

// Range is a host paired with a contiguous, inclusive run of ports, which
// is what share forwards and listen binds. A plain host:port parses as a
// Range of one, so a single-port session is not a special case anywhere
// downstream - it's just the shortest range.
//
// Both ends of a session agree on the number of ports, not the numbers
// themselves: what crosses the wire is an index into the range (see
// proto.PortIndex), so a share on 8000-8010 can be reached by a listen
// bound to 9000-9010, index for index.
type Range struct {
	// base is the first port of the range, paired with the host every
	// port in it shares.
	base HostPort

	// count is how many ports the range spans, always at least 1.
	count int
}

// ParseRange parses "host:port" as a range of one, or "host:first-last" as
// the inclusive run of ports between the two.
func ParseRange(s string) (Range, error) {
	host, portsStr, err := net.SplitHostPort(s)
	if err != nil {
		return Range{}, fmt.Errorf("%w: %w", ErrInvalidHostPort, err)
	}

	first, last, err := parsePortSpan(portsStr)
	if err != nil {
		return Range{}, err
	}

	base, err := newHostPort(host, first)
	if err != nil {
		return Range{}, err
	}

	return Range{base: base, count: int(last) - int(first) + 1}, nil
}

// parsePortSpan parses the port half of a Range: either a lone port, which
// spans only itself, or "first-last". It returns the first and last port
// of the span.
func parsePortSpan(s string) (uint16, uint16, error) {
	firstStr, lastStr, isSpan := strings.Cut(s, "-")

	first, err := parsePort(firstStr)
	if err != nil {
		return 0, 0, err
	}

	if !isSpan {
		return first, first, nil
	}

	last, err := parsePort(lastStr)
	if err != nil {
		return 0, 0, err
	}

	switch {
	case first == 0:
		// Port 0 means "let the OS pick one" - a request that says nothing
		// about the port after it, so it can't be the start of a run.
		return 0, 0, fmt.Errorf("%w: a range cannot start at port 0", ErrInvalidRange)
	case last < first:
		return 0, 0, fmt.Errorf("%w: %d-%d ends before it starts", ErrInvalidRange, first, last)
	case int(last)-int(first)+1 > MaxPorts:
		return 0, 0, fmt.Errorf("%w: %d-%d spans more than %d ports", ErrInvalidRange, first, last, MaxPorts)
	}

	return first, last, nil
}

// Len is how many ports the range spans.
func (r Range) Len() int { return r.count }

// At returns the port at index i, and whether i is within the range at
// all. Callers index it with a number that arrived over the wire - a peer
// naming a port past the end of the range is an error to drop, not a
// panic - so the ok result is not optional the way a slice bound would be.
func (r Range) At(i int) (HostPort, bool) {
	if i < 0 || i >= r.count {
		return HostPort{}, false
	}

	port := r.base
	port.port = r.base.port + uint16(i) //nolint:gosec // parsePortSpan bounds base.port+count-1 at 65535

	return port, true
}

// String renders the range the way ParseRange accepts it.
func (r Range) String() string {
	if r.count <= 1 {
		return r.base.String()
	}

	last, _ := r.At(r.count - 1)

	return r.base.String() + "-" + strconv.Itoa(int(last.port))
}

// UnmarshalText makes this a drop-in scalar type.
func (r *Range) UnmarshalText(b []byte) error {
	parsed, err := ParseRange(string(b))
	if err != nil {
		return err
	}

	*r = parsed
	return nil
}

// MarshalText makes this a drop-in scalar type.
func (r Range) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}
