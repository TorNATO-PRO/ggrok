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
//
//nolint:recvcheck // UnmarshalText needs a pointer receiver to satisfy encoding.TextUnmarshaler; every other method uses a value receiver since HostPort is a small, cheaply-copied value type.
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

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return HostPort{}, fmt.Errorf("%w: bad port: %w", ErrInvalidHostPort, err)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return HostPort{kind: KindIP, ip: ip, port: uint16(port)}, nil
	}

	if host == "" || strings.ContainsAny(host, " \t") {
		return HostPort{}, fmt.Errorf("%w: bad host %q", ErrInvalidHostPort, host)
	}

	return HostPort{kind: KindName, name: host, port: uint16(port)}, nil
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
