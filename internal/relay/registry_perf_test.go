package relay //nolint:testpackage // Verifies private certificate reference counts and timer lifecycle.

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/proto"
)

// certificateConn completes a real handshake to populate ConnectionState.
// The transport can then close: these tests exercise registry bookkeeping.
func certificateConn(t *testing.T) *tls.Conn {
	t.Helper()
	bundle, err := ca.Init("registry test", ca.DefaultCAValidity)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	server := tls.Server(a, &tls.Config{
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAnyClientCert,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	})
	client := tls.Client(b, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Isolated in-memory test handshake.
		MinVersion:         tls.VersionTLS13,
	})
	done := make(chan error, 1)
	go func() { done <- client.Handshake() }()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return server
}

func TestSubscriberCertificateReferences(t *testing.T) {
	t.Parallel()
	conn := certificateConn(t)
	s := newSession(proto.ModeTCP, 1, nil, nil)
	_, releaseA, ok := s.addSubscriber(conn)
	if !ok {
		t.Fatal("first registration rejected")
	}
	_, releaseB, ok := s.addSubscriber(conn)
	if !ok {
		t.Fatal("duplicate certificate registration rejected")
	}
	releaseA()
	releaseA() // release must not decrement the remaining registration twice
	id, ok := s.addPending(conn)
	if !ok {
		t.Fatal("remaining registration lost authorization")
	}
	s.removePending(id)
	releaseB()
	if _, ok := s.addPending(conn); ok {
		t.Fatal("last release retained authorization")
	}
	if len(s.subscriberCerts) != 0 {
		t.Fatal("certificate index retained unused entry")
	}
}

func TestPendingTimerCleanup(t *testing.T) {
	t.Parallel()
	for _, action := range []string{"claim", "remove", "shutdown", "expire"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			conn := certificateConn(t)
			s := newSession(proto.ModeTCP, 1, nil, nil)
			_, release, ok := s.addSubscriber(conn)
			if !ok {
				t.Fatal("registration rejected")
			}
			defer release()
			id, ok := s.addPending(conn)
			if !ok {
				t.Fatal("pending request rejected")
			}
			timer := s.pending[id].timer
			defer timer.Stop()
			switch action {
			case "claim":
				assertClaim(t, s, id, conn)
			case "remove":
				s.removePending(id)
			case "shutdown":
				s.shutdown()
			case "expire":
				timer.Reset(0)
				waitPendingGone(t, s, id)
			}
			if timer.Stop() {
				t.Fatal("completed request left an active timer")
			}
			if _, ok := s.claimPending(id); ok {
				t.Fatal("completed request could be claimed again")
			}
		})
	}
}

func waitPendingGone(t *testing.T, s *session, id uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		_, pending := s.pending[id]
		s.mu.Unlock()
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("request did not expire")
		}
		time.Sleep(time.Millisecond)
	}
}

func assertClaim(t *testing.T, s *session, id uint64, want net.Conn) {
	t.Helper()
	got, ok := s.claimPending(id)
	if !ok || got != want {
		t.Fatal("claim lost connection")
	}
}

// closeCounter checks which competing path takes ownership of a pending socket.
type closeCounter struct {
	net.Conn

	closes atomic.Int32
}

func (c *closeCounter) Close() error {
	c.closes.Add(1)
	return nil
}

func TestPendingConnectionOwnership(t *testing.T) {
	t.Parallel()
	for _, shutdown := range []bool{false, true} {
		name := "timeout"
		if shutdown {
			name = "shutdown"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for range 100 {
				checkPendingOwnership(t, shutdown)
			}
		})
	}
}

func checkPendingOwnership(t *testing.T, shutdown bool) {
	t.Helper()
	s := newSession(proto.ModeTCP, 1, nil, nil)
	conn := &closeCounter{}
	timer := time.AfterFunc(time.Hour, func() { s.removePending(0) })
	defer timer.Stop()
	s.pending[0] = &pendingRequest{conn: conn, timer: timer}
	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-start
		if shutdown {
			s.shutdown()
		} else {
			s.removePending(0) // The timer callback uses this same cleanup path.
		}
	}()
	close(start)
	claimed, ok := s.claimPending(0)
	<-done
	wantCloses := int32(1)
	if ok {
		wantCloses = 0
		if claimed != conn {
			t.Fatal("claim returned a different connection")
		}
	}
	if got := conn.closes.Load(); got != wantCloses {
		t.Fatalf("claimed=%v: connection closed %d times, want %d", ok, got, wantCloses)
	}
	if timer.Stop() {
		t.Fatal("completed request retained an active timer")
	}
}
