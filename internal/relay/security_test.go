package relay_test

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/peer"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/relay"
)

func testTLSConfig(t *testing.T, root *ca.CA, server bool) *tls.Config {
	t.Helper()
	bundle, err := root.Issue(ca.IssueRequest{
		CommonName: "test peer", Server: server, IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"cert.pem": bundle.CertPEM, "key.pem": bundle.KeyPEM, "ca.pem": root.CertPEM,
	} {
		if writeErr := os.WriteFile(filepath.Join(dir, name), data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	cfg, err := mtls.LoadConfig(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "ca.pem"), server, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func registerControl(t *testing.T, addr string, cfg *tls.Config, token proto.Token, role proto.Role) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := proto.WriteConnKind(conn, proto.ConnControl); err != nil {
		t.Fatal(err)
	}
	if err := proto.Handshake(conn, role, proto.ModeTCP, 2, token); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestTunnelCertificateBindingAndRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	bundle, err := ca.Init("test root", ca.DefaultCAValidity)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.Load(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", testTLSConfig(t, root, true))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	logger := slog.New(slog.DiscardHandler)
	registry := relay.NewRegistry(logger)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go relay.HandleConn(ctx, logger, registry, conn.(*tls.Conn))
		}
	}()
	addr, err := hostport.Parse(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	pubCfg, subCfg := testTLSConfig(t, root, false), testTLSConfig(t, root, false)
	pubControl := registerControl(t, addr.String(), pubCfg, token, proto.RolePublish)
	registerControl(t, addr.String(), subCfg, token, proto.RoleSubscribe)

	// Same CN and CA, different leaf: a routing ID and a network certificate
	// must not substitute for that subscriber's control certificate.
	intruder := peer.NewSession(addr, testTLSConfig(t, root, false), token, proto.RoleSubscribe)
	if tunnel, attachErr := intruder.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachSubscriber}); attachErr == nil {
		_ = tunnel.Close()
		t.Fatal("unregistered certificate attached a subscriber stream")
	}

	pub := peer.NewSession(addr, pubCfg, token, proto.RolePublish)
	sub := peer.NewSession(addr, subCfg, token, proto.RoleSubscribe)
	result := make(chan error, 1)
	go func() { result <- echoRequest(ctx, pubControl, pub) }()
	tunnel, err := sub.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachSubscriber, Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	if _, err := tunnel.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err := io.ReadFull(tunnel, data); err != nil || string(data) != "ping" {
		t.Fatalf("round trip = %q, %v", data, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func echoRequest(ctx context.Context, control *tls.Conn, pub peer.Session) error {
	typ, payload, err := proto.ReadControlFrame(control)
	if err != nil {
		return err
	}
	if typ != proto.ControlRequestData {
		return io.ErrUnexpectedEOF
	}
	id, port, err := proto.ReadRequestData(payload)
	if err != nil {
		return err
	}
	tunnel, err := pub.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachPublisher, RequestID: id, Port: port})
	if err != nil {
		return err
	}
	defer tunnel.Close()
	data := make([]byte, 4)
	if _, readErr := io.ReadFull(tunnel, data); readErr != nil {
		return readErr
	}
	_, err = tunnel.Write(data)
	return err
}
