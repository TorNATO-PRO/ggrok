package relay_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
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

// dialControl opens a control connection and runs its handshake, returning
// relay's verdict rather than failing on it - the tests below care about
// which peers relay turns away as much as which it accepts.
func dialControl(
	t *testing.T,
	addr string,
	cfg *tls.Config,
	creds proto.Credentials,
	role proto.Role,
) (*tls.Conn, error) {
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

	return conn, proto.Handshake(conn, role, proto.ModeTCP, 2, creds)
}

func registerControl(
	t *testing.T,
	addr string,
	cfg *tls.Config,
	creds proto.Credentials,
	role proto.Role,
) *tls.Conn {
	t.Helper()
	conn, err := dialControl(t, addr, cfg, creds, role)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// testRelay stands a relay up on a fresh CA and returns its address along
// with that CA, so a test can mint however many distinct peer identities it
// needs against it.
func testRelay(ctx context.Context, t *testing.T) (hostport.HostPort, *ca.CA) {
	t.Helper()

	bundle, err := ca.Init("test root", ca.DefaultCAValidity)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.Load(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	serverTLS := testTLSConfig(t, root, true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	logger := slog.New(slog.DiscardHandler)
	registry := relay.NewRegistry(logger)
	handle := relay.HandleConnFunc(logger, registry, relay.TestServerConfig{Admin: true})
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go handle(ctx, conn, serverTLS)
		}
	}()

	addr, err := hostport.Parse(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	return addr, root
}

// newSession mints a fresh session key and returns the publisher's
// credentials and the subscriber's, exactly as share would derive one and
// hand out the other.
func newSession(t *testing.T) (proto.Credentials, proto.Credentials) {
	t.Helper()

	key, err := proto.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}

	publisher, err := key.Credentials()
	if err != nil {
		t.Fatal(err)
	}

	return publisher, publisher.SubscriberToken().Credentials()
}

// TestSubscriberCannotTakeThePublisherSlot is the hijack this protocol
// version exists to close. A subscriber holds the session's data secret and
// can derive its SessionID, so under the old first-come-wins registration it
// could wait for the real publisher's connection to sever - which relay
// tolerates for a full heartbeat timeout, and which the reconnect backoff is
// deliberately shaped around - register in its place, and serve its own
// service to every other subscriber while the displaced publisher was locked
// out of its own tunnel.
//
// Relay now hands the slot only to a peer that signs for the key the
// SessionID commits to, which a subscriber token does not carry.
func TestSubscriberCannotTakeThePublisherSlot(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root := testRelay(ctx, t)
	publisher, subscriber := newSession(t)

	// An honest build won't even try: Handshake has nothing to sign with.
	// That is defence in depth rather than the defence - an attacker runs
	// whatever build it likes - so it is asserted and then stepped around.
	if _, err := dialControl(
		t, addr.String(), testTLSConfig(t, root, false), subscriber, proto.RolePublish,
	); err == nil {
		t.Fatal("a subscriber's own client produced a publish claim")
	}

	// What an attacker actually sends. The slot is free - nobody has
	// published this session yet - so the claim is the only thing between a
	// forged Hello and the session.
	forged := proto.Hello{
		Role:      proto.RolePublish,
		Mode:      proto.ModeTCP,
		Ports:     2,
		SessionID: subscriber.SessionID(), // which is the publisher's, derived
	}
	if err := forgeClaim(t, addr.String(), testTLSConfig(t, root, false), forged); !errors.Is(err, proto.ErrDenied) {
		t.Fatalf("forged publish claim = %v, want ErrDenied", err)
	}

	// And the real publisher still gets the slot afterwards - a denied claim
	// must not have consumed or poisoned it on the way out.
	registerControl(t, addr.String(), testTLSConfig(t, root, false), publisher, proto.RolePublish)
}

// forgeClaim registers hello with a fabricated answer to relay's challenge,
// which is the best a peer without the session key can do, and returns
// relay's verdict. A relay that hung up rather than acking is reported as a
// denial: it is one, and the distinction is not what this test is about.
func forgeClaim(t *testing.T, addr string, cfg *tls.Config, hello proto.Hello) error {
	t.Helper()

	conn, dialErr := tls.Dial("tcp", addr, cfg)
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := proto.WriteConnKind(conn, proto.ConnControl); err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteHello(conn, hello); err != nil {
		t.Fatal(err)
	}

	var challenge [32]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return proto.ErrDenied
	}

	proof := make([]byte, forgedProofSize)
	if _, err := rand.Read(proof); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(proof); err != nil {
		return proto.ErrDenied
	}

	status, ackErr := proto.ReadAck(conn)
	if ackErr != nil {
		return proto.ErrDenied
	}

	return status.Err()
}

// forgedProofSize is the width of an ML-DSA-65 public key plus a signature,
// which is what relay reads before it decides. A forgery has to be the right
// length to even reach the check that rejects it.
const forgedProofSize = 1952 + 3309

func TestTunnelCertificateBindingAndRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	addr, root := testRelay(ctx, t)
	publisher, subscriber := newSession(t)

	pubCfg, subCfg := testTLSConfig(t, root, false), testTLSConfig(t, root, false)
	pubControl := registerControl(t, addr.String(), pubCfg, publisher, proto.RolePublish)
	registerControl(t, addr.String(), subCfg, subscriber, proto.RoleSubscribe)

	// Same CN and CA, different leaf: a routing ID and a network certificate
	// must not substitute for that subscriber's control certificate.
	intruder := peer.NewSession(addr, testTLSConfig(t, root, false), subscriber, proto.RoleSubscribe)
	if tunnel, attachErr := intruder.OpenTunnel(ctx, proto.Attach{Kind: proto.AttachSubscriber}); attachErr == nil {
		_ = tunnel.Close()
		t.Fatal("unregistered certificate attached a subscriber stream")
	}

	pub := peer.NewSession(addr, pubCfg, publisher, proto.RolePublish)
	sub := peer.NewSession(addr, subCfg, subscriber, proto.RoleSubscribe)
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
