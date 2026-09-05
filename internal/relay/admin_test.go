package relay_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/relay"
)

// roleTLSConfig builds a client config whose certificate carries the given
// role, so a test can present an admin identity and an ordinary one to the
// same relay.
func roleTLSConfig(t *testing.T, root *ca.CA, admin bool) *tls.Config {
	t.Helper()

	bundle, err := root.Issue(ca.IssueRequest{
		CommonName: "test operator",
		Validity:   ca.DefaultDeviceValidity,
		Admin:      admin,
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
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
		filepath.Join(dir, "ca.pem"), false, nil)
	if err != nil {
		t.Fatal(err)
	}

	return cfg
}

// adminRelay stands a relay up with the admin plane either enabled or not,
// returning its address, its CA, and the registry so a test can inspect the
// same state the admin plane serves.
func adminRelay(
	ctx context.Context,
	t *testing.T,
	cfg relay.TestServerConfig,
) (hostport.HostPort, *ca.CA, *relay.Registry) {
	t.Helper()

	bundle, err := ca.Init("admin test root", ca.DefaultCAValidity)
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
	handle := relay.HandleConnFunc(logger, registry, cfg)
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

	return addr, root, registry
}

// dialAdmin opens an admin connection and completes the hello exchange,
// returning relay's ack rather than failing on a refusal - which peers relay
// turns away is exactly what these tests are about.
func dialAdmin(t *testing.T, addr string, cfg *tls.Config) (*tls.Conn, proto.AdminAckPayload, error) {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if writeErr := proto.WriteAdminHello(conn,
		proto.AdminHelloPayload{Version: proto.AdminVersion}); writeErr != nil {
		t.Fatal(writeErr)
	}

	typ, body, err := proto.ReadAdminFrame(conn)
	if err != nil {
		return conn, proto.AdminAckPayload{}, err
	}
	if typ != proto.AdminAck {
		t.Fatalf("relay answered the admin hello with %s", typ)
	}

	var ack proto.AdminAckPayload
	if decodeErr := proto.DecodeAdminPayload(body, &ack); decodeErr != nil {
		t.Fatal(decodeErr)
	}

	return conn, ack, nil
}

// TestAdminRequiresBothGates is the authorization story in one test: the
// relay's own opt-in and the certificate's role are independent, and either
// one closed is enough to refuse.
func TestAdminRequiresBothGates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		relayAdmin   bool
		certAdmin    bool
		wantAccepted bool
		// wantAnswered distinguishes a refusal relay explains from one it
		// does not. A relay with the plane disabled says nothing at all,
		// so a scan cannot learn which relays are worth returning to with
		// a better certificate.
		wantAnswered bool
	}{
		{name: "both gates open", relayAdmin: true, certAdmin: true, wantAccepted: true, wantAnswered: true},
		{name: "cert lacks the role", relayAdmin: true, certAdmin: false, wantAnswered: true},
		{name: "relay plane disabled", relayAdmin: false, certAdmin: true},
		{name: "neither", relayAdmin: false, certAdmin: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			addr, root, _ := adminRelay(ctx, t, relay.TestServerConfig{Admin: tt.relayAdmin})
			_, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, tt.certAdmin))

			if !tt.wantAnswered {
				if err == nil {
					t.Fatal("a disabled admin plane answered instead of closing")
				}

				return
			}
			if err != nil {
				t.Fatalf("relay did not answer: %v", err)
			}
			if ack.OK != tt.wantAccepted {
				t.Fatalf("ack.OK = %v (%q), want %v", ack.OK, ack.Err, tt.wantAccepted)
			}
			if !tt.wantAccepted && ack.Err == "" {
				t.Fatal("a refusal carried no reason")
			}
		})
	}
}

// TestAdminListReflectsLiveSessions walks the whole path an operator does:
// a publisher registers, a subscriber attaches, and the snapshot names both
// by the identity the CA vouched for.
func TestAdminListReflectsLiveSessions(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, _ := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})
	clientCfg := testTLSConfig(t, root, false)
	pub, sub := newSession(t)

	conn, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	if got := requestSnapshot(t, conn); len(got.Sessions) != 0 {
		t.Fatalf("a fresh relay reported %d sessions", len(got.Sessions))
	}

	registerControl(t, addr.String(), clientCfg, pub, proto.RolePublish)
	registerControl(t, addr.String(), clientCfg, sub, proto.RoleSubscribe)

	snapshot := requestSnapshot(t, conn)
	if len(snapshot.Sessions) != 1 {
		t.Fatalf("snapshot has %d sessions, want 1", len(snapshot.Sessions))
	}

	sess := snapshot.Sessions[0]
	if sess.Tag != pub.SessionID().LogTag() {
		t.Fatalf("tag = %q, want %q", sess.Tag, pub.SessionID().LogTag())
	}
	if len(sess.Tag) == len(pub.SessionID())*2 {
		t.Fatal("the snapshot carried a full SessionID, not a log tag")
	}
	if sess.Mode != "tcp" || sess.Ports != 2 {
		t.Fatalf("session = %+v", sess)
	}
	if sess.Publisher.CN == "" || sess.Publisher.Serial == "" || sess.Publisher.Addr == "" {
		t.Fatalf("publisher identity incomplete: %+v", sess.Publisher)
	}
	if len(sess.Subscribers) != 1 {
		t.Fatalf("snapshot has %d subscribers, want 1", len(sess.Subscribers))
	}
	if sess.Subscribers[0].CN == "" || sess.Subscribers[0].Serial == "" {
		t.Fatalf("subscriber identity incomplete: %+v", sess.Subscribers[0])
	}
	if len(sess.Streams) != 0 {
		t.Fatalf("snapshot reported %d streams before any traffic", len(sess.Streams))
	}
}

// TestSnapshotUnderConcurrentChurn is the race-detector's shot at the
// bookkeeping: a snapshot must never block, deadlock, or observe a torn map
// while sessions come and go underneath it.
func TestSnapshotUnderConcurrentChurn(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, registry := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})
	clientCfg := testTLSConfig(t, root, false)

	const sessions = 8
	var wg sync.WaitGroup
	for range sessions {
		pub, sub := newSession(t)
		wg.Go(func() {
			pubConn, err := dialControl(t, addr.String(), clientCfg, pub, proto.RolePublish)
			if err != nil {
				return
			}
			subConn, err := dialControl(t, addr.String(), clientCfg, sub, proto.RoleSubscribe)
			if err == nil {
				_ = subConn.Close()
			}
			_ = pubConn.Close()
		})
	}

	// Snapshot continuously while the above churns. The assertion is the
	// absence of a race report or a hang, not any particular count.
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()
	for {
		select {
		case <-done:
			registry.Snapshot() // one last one, after the churn settles
			return
		default:
			for _, sess := range registry.Snapshot().Sessions {
				if sess.Tag == "" {
					t.Error("snapshot produced a session with no tag")
					return
				}
			}
		}
	}
}

// requestSnapshot asks an already-authorized admin connection for one
// snapshot.
func requestSnapshot(t *testing.T, conn *tls.Conn) proto.Snapshot {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := proto.WriteAdminFrame(conn, proto.AdminList, nil); err != nil {
		t.Fatal(err)
	}

	typ, body, err := proto.ReadAdminFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.AdminSnapshot {
		t.Fatalf("relay answered a list with %s", typ)
	}

	var snapshot proto.Snapshot
	if err := proto.DecodeAdminPayload(body, &snapshot); err != nil {
		t.Fatal(err)
	}

	return snapshot
}

// TestAdminUnknownRequestIsAnswered covers the forward-compatibility arm: an
// admin client and a relay can be different builds, and the self-describing
// schema exists so that mismatch is a conversation rather than a dropped
// connection.
func TestAdminUnknownRequestIsAnswered(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, _ := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})
	conn, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if writeErr := proto.WriteAdminFrame(conn, proto.AdminType(200), nil); writeErr != nil {
		t.Fatal(writeErr)
	}

	typ, body, err := proto.ReadAdminFrame(conn)
	if err != nil {
		t.Fatalf("relay dropped the connection instead of answering: %v", err)
	}
	if typ != proto.AdminResult {
		t.Fatalf("relay answered an unknown request with %s", typ)
	}

	var result proto.AdminResultPayload
	if err := proto.DecodeAdminPayload(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.OK {
		t.Fatal("an unknown request was reported as successful")
	}

	// The connection must still be usable: an unknown frame is not fatal.
	if got := requestSnapshot(t, conn); got.Now.IsZero() {
		t.Fatal("the connection was unusable after an unknown request")
	}
}

// requestMutation sends one mutating request on an authorized admin
// connection and returns relay's verdict.
func requestMutation(t *testing.T, conn *tls.Conn, typ proto.AdminType, payload any) proto.AdminResultPayload {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := proto.WriteAdminFrame(conn, typ, payload); err != nil {
		t.Fatal(err)
	}

	got, body, err := proto.ReadAdminFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if got != proto.AdminResult {
		t.Fatalf("relay answered a %s with %s", typ, got)
	}

	var result proto.AdminResultPayload
	if decodeErr := proto.DecodeAdminPayload(body, &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}

	return result
}

// TestKickSerialClosesTheSession is the enforcement half of revocation.
// Reloading a CRL only affects the next handshake, so a peer that
// authenticated before the revocation stays connected until something closes
// it - and this is that something.
func TestKickSerialClosesTheSession(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, registry := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})
	clientCfg := testTLSConfig(t, root, false)
	pub, sub := newSession(t)

	pubConn := registerControl(t, addr.String(), clientCfg, pub, proto.RolePublish)
	registerControl(t, addr.String(), clientCfg, sub, proto.RoleSubscribe)

	before := registry.Snapshot()
	if len(before.Sessions) != 1 {
		t.Fatalf("setup produced %d sessions, want 1", len(before.Sessions))
	}
	serial := before.Sessions[0].Publisher.Serial
	if serial == "" {
		t.Fatal("the snapshot carried no serial to kick by")
	}

	// An unrelated serial must close nothing: a kick is targeted, and one
	// that quietly took down bystanders would be far worse than one that
	// missed.
	admin, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}
	kick := func(serial string) int {
		return requestMutation(t, admin, proto.AdminKick, proto.AdminKickPayload{Serial: serial}).Affected
	}
	if closed := kick("0000deadbeef"); closed != 0 {
		t.Fatalf("kicking an unknown serial closed %d connections", closed)
	}
	if len(registry.Snapshot().Sessions) != 1 {
		t.Fatal("kicking an unknown serial disturbed a live session")
	}
	if closed := kick(""); closed != 0 {
		t.Fatalf("kicking an empty serial closed %d connections", closed)
	}

	// Publisher and subscriber share one identity here, so both control
	// connections belong to this serial.
	closed := kick(serial)
	if closed != 2 {
		t.Fatalf("kick closed %d connections, want 2", closed)
	}

	// Closing the publisher's control connection runs the ordinary
	// unregister path, which drops the session.
	waitForNoSessions(t, registry)

	// The peer observes a closed connection, which is what makes its
	// existing reconnect logic take over - no new frame type involved.
	_ = pubConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf [1]byte
	if _, err := pubConn.Read(buf[:]); err == nil {
		t.Fatal("a kicked publisher's control connection was still readable")
	}
}

// waitForNoSessions waits for the registry to become empty. The kick
// closes connections; the unregister that drops the session happens on the
// handler goroutine a moment later.
func waitForNoSessions(t *testing.T, registry *relay.Registry) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		got := len(registry.Snapshot().Sessions)
		if got == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry still has %d sessions", got)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAdminKickOverTheWire drives the kick through the admin plane rather
// than the registry directly, so the request decoding and the result frame
// are covered too.
func TestAdminKickOverTheWire(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, registry := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})
	clientCfg := testTLSConfig(t, root, false)
	pub, _ := newSession(t)
	registerControl(t, addr.String(), clientCfg, pub, proto.RolePublish)

	conn, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	snapshot := requestSnapshot(t, conn)
	if len(snapshot.Sessions) != 1 {
		t.Fatalf("setup produced %d sessions, want 1", len(snapshot.Sessions))
	}
	serial := snapshot.Sessions[0].Publisher.Serial

	// A kick with no serial is refused rather than treated as "kick
	// everything", which is the failure mode worth being loud about.
	if empty := requestMutation(t, conn, proto.AdminKick, proto.AdminKickPayload{}); empty.OK {
		t.Fatal("a kick with no serial was accepted")
	}

	result := requestMutation(t, conn, proto.AdminKick, proto.AdminKickPayload{Serial: serial})
	if !result.OK || result.Affected != 1 {
		t.Fatalf("kick = %+v, want ok with 1 affected", result)
	}

	waitForNoSessions(t, registry)
}

// TestAdminReloadCRLWithoutAFile covers the arm an operator hits by running
// reload-crl against a relay started without -revoked-file: there is nothing
// to reload, and saying so beats silently reporting success.
func TestAdminReloadCRLWithoutAFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, _ := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})
	conn, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	result := requestMutation(t, conn, proto.AdminReloadCRL, nil)
	if result.OK {
		t.Fatal("reload-crl reported success with no revoked file configured")
	}
	if result.Detail == "" {
		t.Fatal("the refusal carried no explanation")
	}
}

// TestAdminReloadCRLEnforces is the whole point of the phase: `ca revoke`
// has to reach a relay that is already running, and reach the peers that are
// already connected to it.
//
// Reloading alone would only affect the next handshake, leaving an
// already-authenticated peer connected indefinitely. Both halves are asserted
// here: the set the listener consults changes, and the live session goes.
func TestAdminReloadCRLEnforces(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	revokedFile := filepath.Join(t.TempDir(), "revoked.txt")
	if err := os.WriteFile(revokedFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	revoked := mtls.NewRevocationSet(nil)

	addr, root, registry := adminRelay(ctx, t, relay.TestServerConfig{
		Admin: true, Revoked: revoked, RevokedFile: revokedFile,
	})
	clientCfg := testTLSConfig(t, root, false)
	pub, _ := newSession(t)
	registerControl(t, addr.String(), clientCfg, pub, proto.RolePublish)

	conn, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	snapshot := requestSnapshot(t, conn)
	if len(snapshot.Sessions) != 1 {
		t.Fatalf("setup produced %d sessions, want 1", len(snapshot.Sessions))
	}
	serial := snapshot.Sessions[0].Publisher.Serial

	// An unchanged file reloads cleanly and closes nothing - reload must be
	// safe to run when nothing has changed.
	quiet := requestMutation(t, conn, proto.AdminReloadCRL, nil)
	if !quiet.OK || quiet.Affected != 0 {
		t.Fatalf("reload of an empty list = %+v, want ok with 0 affected", quiet)
	}
	if len(registry.Snapshot().Sessions) != 1 {
		t.Fatal("reloading an unchanged list disturbed a live session")
	}

	if err := os.WriteFile(revokedFile, []byte(serial+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result := requestMutation(t, conn, proto.AdminReloadCRL, nil)
	if !result.OK || result.Affected == 0 {
		t.Fatalf("reload = %+v, want ok with connections closed", result)
	}
	if !revoked.Contains(serial) {
		t.Fatal("the reload did not reach the set the listener consults")
	}
	waitForNoSessions(t, registry)

	// A second reload of the same list must not re-report the same serial:
	// it cannot have reconnected, so a non-zero count would be a lie.
	again := requestMutation(t, conn, proto.AdminReloadCRL, nil)
	if !again.OK || again.Affected != 0 {
		t.Fatalf("re-reloading the same list = %+v, want ok with 0 affected", again)
	}
}

// TestAdminReloadCRLRejectsAnUnreadableFile covers the arm where the operator
// points relay at something it cannot parse. The old set must survive: a
// failed reload that silently emptied the revocation list would un-revoke
// every peer at once.
func TestAdminReloadCRLRejectsAnUnreadableFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	revoked := mtls.NewRevocationSet(map[string]struct{}{"aa": {}})
	addr, root, _ := adminRelay(ctx, t, relay.TestServerConfig{
		Admin: true, Revoked: revoked, RevokedFile: filepath.Join(t.TempDir(), "does-not-exist.txt"),
	})

	conn, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	result := requestMutation(t, conn, proto.AdminReloadCRL, nil)
	if result.OK {
		t.Fatal("reloading a missing file reported success")
	}
	if !revoked.Contains("aa") {
		t.Fatal("a failed reload discarded the revocation list that was already in force")
	}
}

func TestReloadRevokesExistingAdminConnection(t *testing.T) {
	t.Parallel()
	revokedFile := filepath.Join(t.TempDir(), "revoked.txt")
	if err := os.WriteFile(revokedFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	addr, root, _ := adminRelay(t.Context(), t, relay.TestServerConfig{
		Admin: true, Revoked: mtls.NewRevocationSet(nil), RevokedFile: revokedFile,
	})
	victimCfg := roleTLSConfig(t, root, true)
	victim, ack, err := dialAdmin(t, addr.String(), victimCfg)
	if err != nil || !ack.OK {
		t.Fatalf("victim admin refused: %v %+v", err, ack)
	}
	operator, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("operator refused: %v %+v", err, ack)
	}
	cert, err := x509.ParseCertificate(victimCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	serialLine := []byte(cert.SerialNumber.Text(ca.SerialTextBase) + "\n")
	if writeErr := os.WriteFile(revokedFile, serialLine, 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	result := requestMutation(t, operator, proto.AdminReloadCRL, nil)
	if !result.OK || result.Affected != 1 {
		t.Fatalf("reload: %+v", result)
	}
	_ = victim.SetReadDeadline(time.Now().Add(time.Second))
	var timeout net.Error
	if _, _, readErr := proto.ReadAdminFrame(victim); readErr == nil {
		t.Fatal("revoked admin remains connected")
	} else if errors.As(readErr, &timeout) && timeout.Timeout() {
		t.Fatal("revoked admin was not closed")
	}
	// This test listener deliberately has no TLS revocation callback: the
	// dispatcher's admission check must independently reject stale handshakes.
	_, ack, err = dialAdmin(t, addr.String(), victimCfg)
	if err == nil && ack.OK {
		t.Fatal("revoked admin readmitted")
	}
}

func TestKickClosesStreamAfterSessionEnds(t *testing.T) {
	t.Parallel()
	addr, root, registry := adminRelay(t.Context(), t, relay.TestServerConfig{Admin: true})
	pubCfg, subCfg := testTLSConfig(t, root, false), testTLSConfig(t, root, false)
	pub, sub := newSession(t)
	control := registerControl(t, addr.String(), pubCfg, pub, proto.RolePublish)
	registerControl(t, addr.String(), subCfg, sub, proto.RoleSubscribe)
	serial := registry.Snapshot().Sessions[0].Publisher.Serial
	dialData := func(cfg *tls.Config, attach proto.Attach) *tls.Conn {
		conn, err := tls.Dial("tcp", addr.String(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := proto.WriteDataAttach(conn, attach); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	subscriber := dialData(subCfg, proto.Attach{Kind: proto.AttachSubscriber, SessionID: sub.SessionID()})
	if ack, err := proto.ReadAck(subscriber); err != nil || ack != proto.AckOK {
		t.Fatalf("attach: %v %v", ack, err)
	}
	_, payload, err := proto.ReadControlFrame(control)
	if err != nil {
		t.Fatal(err)
	}
	id, port, err := proto.ReadRequestData(payload)
	if err != nil {
		t.Fatal(err)
	}
	publisher := dialData(pubCfg, proto.Attach{
		Kind: proto.AttachPublisher, SessionID: pub.SessionID(), RequestID: id, Port: port,
	})
	// Relay only splices opaque bytes; a round trip establishes that pairing finished.
	if _, err = publisher.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err = io.ReadFull(subscriber, data[:]); err != nil {
		t.Fatal(err)
	}
	_ = control.Close()
	waitForNoSessions(t, registry)
	if _, err = publisher.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(subscriber, data[:]); err != nil {
		t.Fatalf("stream did not survive control loss: %v", err)
	}
	admin, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}
	result := requestMutation(t, admin, proto.AdminKick, proto.AdminKickPayload{Serial: serial})
	if !result.OK || result.Affected != 1 {
		t.Fatalf("kick retired stream: %+v", result)
	}
	var timeout net.Error
	if _, readErr := subscriber.Read(data[:]); readErr == nil || (errors.As(readErr, &timeout) && timeout.Timeout()) {
		t.Fatalf("retired stream was not closed: %v", readErr)
	}
}
