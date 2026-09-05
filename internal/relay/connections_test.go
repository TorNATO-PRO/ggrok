package relay //nolint:testpackage // Tests private socket accounting and shutdown invariants.

import (
	"net"
	"testing"
)

func TestConnectionLimitAndShutdown(t *testing.T) {
	t.Parallel()
	var set connectionSet
	for range maxConnections {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		if _, ok := set.track(a); !ok {
			t.Fatal("connection rejected below the limit")
		}
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, ok := set.track(a); ok {
		t.Fatal("connection accepted above the limit")
	}
	set.closeAll()
	conn, ok := set.track(a)
	if !ok {
		t.Fatal("shutdown did not release connection slots")
	}
	_ = conn.Close()
	if len(set.conns) != 0 {
		t.Fatal("closing a connection did not release its slot")
	}
}
