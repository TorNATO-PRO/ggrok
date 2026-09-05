package relay

import (
	"net"
	"sync"

	"tornato.dev/ggrok/v2/internal/mtls"
)

// maxConnections bounds relay sockets, including unauthenticated TLS handshakes,
// control connections, pending attaches, and both halves of active streams.
const maxConnections = 1024

type connectionSet struct {
	mu sync.Mutex

	conns map[net.Conn]string
}

func (s *connectionSet) track(conn net.Conn) (net.Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) >= maxConnections {
		return nil, false
	}
	if s.conns == nil {
		s.conns = make(map[net.Conn]string)
	}
	s.conns[conn] = ""
	return &trackedConn{Conn: conn, set: s}, true
}

// authenticate closes the gap between TLS verification and live admission.
// Reload publishes its revocation set before scanning under this same lock.
func (s *connectionSet) authenticate(conn net.Conn, serial string, revoked *mtls.RevocationSet) bool {
	tracked, ok := conn.(*trackedConn)
	if !ok || tracked.set != s || serial == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.conns[tracked.Conn]; !ok || (revoked != nil && revoked.Contains(serial)) {
		return false
	}
	s.conns[tracked.Conn] = serial
	return true
}

// closeMatching covers every authenticated socket, independently of sessions.
// Close raw transports outside the lock so TLS writes cannot delay eviction.
func (s *connectionSet) closeMatching(matches func(string) bool) int {
	s.mu.Lock()
	var conns []net.Conn
	for conn, serial := range s.conns {
		if serial != "" && matches(serial) {
			conns = append(conns, conn)
			delete(s.conns, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return len(conns)
}

// closeAll runs after the accept loop has stopped, so no new sockets can join.
func (s *connectionSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	clear(s.conns)
}

type trackedConn struct {
	net.Conn

	set *connectionSet
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.set.mu.Lock()
	delete(c.set.conns, c.Conn)
	c.set.mu.Unlock()
	return err
}
