package relay_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/listen"
	"tornato.dev/ggrok/v2/internal/peer"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/share"
)

func peerFiles(t *testing.T, root *ca.CA) (string, string, string) {
	t.Helper()
	bundle, err := root.Issue(ca.IssueRequest{CommonName: "usability test"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"cert.pem": bundle.CertPEM, "key.pem": bundle.KeyPEM, "ca.pem": root.CertPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "ca.pem")
}

func usabilityRange(t *testing.T, addr string) hostport.Range {
	t.Helper()
	ports, err := hostport.ParseRange(addr)
	if err != nil {
		t.Fatal(err)
	}
	return ports
}

func awaitEvent[T any](t *testing.T, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
	}
	var zero T
	return zero
}

// TestListenWaitAndForward exercises readiness against a real relay and local
// service, including a client arriving too early and a service going away.
func TestListenWaitAndForward(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, root := testRelay(ctx, t)
	certFile, keyFile, caFile := peerFiles(t, root)
	key, err := proto.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	creds, err := key.Credentials()
	if err != nil {
		t.Fatal(err)
	}

	bound := make(chan net.Addr, 1)
	ready := make(chan struct{}, 1)
	reconnected := make(chan struct{}, 1)
	disconnected := make(chan error, 16)
	waiting := make(chan error, 16)
	forwardErrors := make(chan error, 16)
	listenDone := make(chan error, 1)
	listenAddr := usabilityRange(t, "127.0.0.1:0")
	go func() {
		listenDone <- listen.Run(ctx, listen.Config{
			Server: addr, CertFile: certFile, KeyFile: keyFile, CAFile: caFile,
			Mode: proto.ModeTCP, Addr: listenAddr, Token: creds.SubscriberToken(), Wait: true,
			OnListen:       func(addr net.Addr) { bound <- addr },
			OnReady:        func() error { ready <- struct{}{}; return nil },
			OnWaiting:      func(err error, _ time.Duration) { waiting <- err },
			OnForwardError: func(err error) { forwardErrors <- err },
			OnReconnect:    func() { reconnected <- struct{}{} },
			OnDisconnect:   func(err error, _ time.Duration) { disconnected <- err },
		})
	}()
	localAddr := awaitEvent(t, bound).String()
	if waitingErr := awaitEvent(t, waiting); !errors.Is(waitingErr, proto.ErrNoSuchSession) {
		t.Fatalf("waiting: %v", waitingErr)
	}
	select {
	case <-ready:
		t.Fatal("ready before publisher exists")
	default:
	}
	early := dialLocal(t, localAddr)
	if _, readErr := early.Read(make([]byte, 1)); readErr == nil {
		t.Fatal("early client was not closed")
	}
	if forwardErr := awaitEvent(t, forwardErrors); !strings.Contains(forwardErr.Error(), "not ready") {
		t.Fatalf("early client: %v", forwardErr)
	}

	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	serviceAddr := service.Addr().String()
	go func() {
		conn, err := service.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()
	shareReady := make(chan struct{}, 1)
	shareErrors := make(chan error, 16)
	shareDone := make(chan error, 1)
	shareAddr := usabilityRange(t, serviceAddr)
	shareCfg := share.Config{
		Server: addr, CertFile: certFile, KeyFile: keyFile, CAFile: caFile,
		Mode: proto.ModeTCP, Addr: shareAddr, SessionKey: key,
		OnReady:        func() error { shareReady <- struct{}{}; return nil },
		OnForwardError: func(err error) { shareErrors <- err },
	}
	shareCtx, stopShare := context.WithCancel(ctx)
	defer stopShare()
	go func() { shareDone <- share.Run(shareCtx, shareCfg) }()
	awaitEvent(t, shareReady)
	awaitEvent(t, ready)
	conn := dialLocal(t, localAddr)
	const payload = "traffic after publisher becomes ready"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != payload {
		t.Fatalf("reply: %q", reply)
	}
	_ = conn.Close()

	_ = service.Close()
	failed := dialLocal(t, localAddr)
	if _, err := failed.Read(make([]byte, 1)); err == nil {
		t.Fatal("unreachable service did not close client")
	}
	serviceErr := awaitEvent(t, shareErrors)
	if !strings.Contains(serviceErr.Error(), serviceAddr) ||
		!strings.Contains(serviceErr.Error(), "service is running") {
		t.Fatalf("missing actionable local service error: %v", serviceErr)
	}
	stopShare()
	if err := awaitEvent(t, shareDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop share: %v", err)
	}
	awaitEvent(t, disconnected)
	go func() { shareDone <- share.Run(ctx, shareCfg) }()
	awaitEvent(t, shareReady)
	awaitEvent(t, reconnected)
	select {
	case <-ready:
		t.Fatal("reconnect repeated initial readiness")
	case <-bound:
		t.Fatal("reconnect rebound the listener")
	default:
	}
	cancel()
	for _, done := range []<-chan error{listenDone, shareDone} {
		if err := awaitEvent(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown: %v", err)
		}
	}
}

func dialLocal(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// TestStartupWaitPolicy checks that opting in only waits out recoverable
// conditions, that cancellation works, and that failed starts never say ready.
func TestStartupWaitPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                          string
		wait, publisher, cancelOnWait bool
		want                          error
	}{
		{name: "default fails for absent publisher", want: proto.ErrNoSuchSession},
		{name: "wait can be canceled", wait: true, cancelOnWait: true, want: context.Canceled},
		{name: "wait rejects mismatched ports", wait: true, publisher: true, want: proto.ErrPortsMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			addr, root := testRelay(ctx, t)
			pub, sub := newSession(t)
			if tt.publisher {
				registerControl(t, addr.String(), testTLSConfig(t, root, false), pub, proto.RolePublish)
			}
			session := peer.NewSession(addr, testTLSConfig(t, root, false), sub, proto.RoleSubscribe)
			done := make(chan error, 1)
			go func() {
				done <- session.Serve(ctx, peer.ServeConfig{
					Mode: proto.ModeTCP, Ports: 1, Wait: tt.wait,
					Handle:  func(proto.ControlType, []byte) error { return nil },
					OnReady: func() error { t.Error("unexpected readiness"); return nil },
					OnWaiting: func(err error, _ time.Duration) {
						if !tt.cancelOnWait {
							t.Errorf("unexpected retry: %v", err)
						}
						cancel()
					},
				})
			}()
			if err := awaitEvent(t, done); !errors.Is(err, tt.want) {
				t.Fatalf("Serve: %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReadyFailureClosesSession(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, root := testRelay(ctx, t)
	pub, _ := newSession(t)
	session := peer.NewSession(addr, testTLSConfig(t, root, false), pub, proto.RolePublish)
	want := errors.New("could not save token")
	done := make(chan error, 1)
	go func() {
		done <- session.Serve(ctx, peer.ServeConfig{
			Mode: proto.ModeTCP, Ports: 1, Wait: true,
			OnReady:   func() error { return want },
			OnWaiting: func(err error, _ time.Duration) { t.Errorf("unexpected retry: %v", err) },
		})
	}()
	if err := awaitEvent(t, done); !errors.Is(err, want) {
		t.Fatalf("Serve: %v", err)
	}
}
