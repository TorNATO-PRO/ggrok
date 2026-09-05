package relay

import (
	"net"
	"sync"
)

// maxConnections bounds relay sockets, including unauthenticated TLS handshakes,
// control connections, pending attaches, and both halves of active streams.
const maxConnections = 1024

type connectionSet struct {
	mu sync.Mutex

	conns map[net.Conn]struct{}
}

func (s *connectionSet) track(conn net.Conn) (net.Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) >= maxConnections {
		return nil, false
	}
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[conn] = struct{}{}
	return &trackedConn{Conn: conn, set: s}, true
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
