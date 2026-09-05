package relay //nolint:testpackage // Tests private socket accounting and shutdown invariants.

import (
	"net"
	"testing"

	"tornato.dev/ggrok/v2/internal/mtls"
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

// A connection can finish TLS before reload and reach admission afterwards.
func TestRevocationAdmissionAndEviction(t *testing.T) {
	t.Parallel()
	var set connectionSet
	revoked := mtls.NewRevocationSet(nil)
	a, b := net.Pipe()
	defer b.Close()
	tracked, _ := set.track(a)
	defer tracked.Close()
	if !set.authenticate(tracked, "123", revoked) {
		t.Fatal("admission failed")
	}
	revoked.Replace(map[string]struct{}{"123": {}})
	if n := set.closeMatching(revoked.Contains); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("revoked transport stayed open")
	}
	if n := set.closeMatching(revoked.Contains); n != 0 {
		t.Fatalf("duplicate eviction: %d", n)
	}
	c, d := net.Pipe()
	defer d.Close()
	late, _ := set.track(c)
	defer late.Close()
	if set.authenticate(late, "123", revoked) {
		t.Fatal("admitted a peer verified before reload")
	}
}
