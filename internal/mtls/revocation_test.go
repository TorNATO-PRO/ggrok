package mtls_test

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/mtls"
)

// bundleDir writes an issued bundle to a temp directory and returns its path,
// since LoadConfig reads identities off disk.
func bundleDir(t *testing.T, bundle *ca.Bundle, rootPEM []byte) string {
	t.Helper()

	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"cert.pem": bundle.CertPEM, "key.pem": bundle.KeyPEM, "ca.pem": rootPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// revocationHarness is a live TLS listener plus the handle controlling which
// serials it refuses, so a test can swap the set between handshakes.
type revocationHarness struct {
	addr      string
	clientCfg *tls.Config
	revoked   *mtls.RevocationSet
	serial    string

	// serverErrs carries each accepted connection's server-side handshake
	// verdict. A rejected client only ever sees a generic "bad certificate"
	// alert - TLS deliberately does not tell it why - so the specific
	// reason is only assertable from this side.
	serverErrs chan error
}

// newRevocationHarness stands up a server whose revocation set starts as
// startWith. Passing nil for startWith is the case that matters most: a relay
// started with no CRL at all must still be able to gain one.
func newRevocationHarness(t *testing.T, startWith map[string]struct{}) *revocationHarness {
	t.Helper()

	rootBundle, err := ca.Init("revocation test root", ca.DefaultCAValidity)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.Load(rootBundle.CertPEM, rootBundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	serverBundle, err := root.Issue(ca.IssueRequest{
		CommonName: "relay", Validity: ca.DefaultDeviceValidity, Server: true,
		IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientBundle, err := root.Issue(ca.IssueRequest{
		CommonName: "node", Validity: ca.DefaultDeviceValidity,
	})
	if err != nil {
		t.Fatal(err)
	}

	revoked := mtls.NewRevocationSet(startWith)
	serverDir := bundleDir(t, serverBundle, root.CertPEM)
	serverCfg, err := mtls.LoadConfig(filepath.Join(serverDir, "cert.pem"), filepath.Join(serverDir, "key.pem"),
		filepath.Join(serverDir, "ca.pem"), true, revoked)
	if err != nil {
		t.Fatal(err)
	}

	clientDir := bundleDir(t, clientBundle, root.CertPEM)
	clientCfg, err := mtls.LoadConfig(filepath.Join(clientDir, "cert.pem"), filepath.Join(clientDir, "key.pem"),
		filepath.Join(clientDir, "ca.pem"), false, nil)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	serverErrs := make(chan error, 16)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				// The handshake is lazy until a read or write, and it is
				// where the revocation check runs.
				err := conn.(*tls.Conn).Handshake()
				serverErrs <- err
				if err == nil {
					_, _ = conn.Write([]byte{0})
				}
			}()
		}
	}()

	return &revocationHarness{
		addr:       ln.Addr().String(),
		clientCfg:  clientCfg,
		revoked:    revoked,
		serial:     clientBundle.Cert.SerialNumber.Text(ca.SerialTextBase),
		serverErrs: serverErrs,
	}
}

// handshake attempts one connection and reports whether the server accepted
// it.
//
// It reads rather than stopping at Handshake, because in TLS 1.3 the client
// finishes its side before the server has processed the client Certificate -
// so a client-side Handshake returns nil even when the server is about to
// reject the peer. The server's verdict arrives as an alert on the first
// read, which is exactly how a real peer learns it has been revoked.
func (h *revocationHarness) handshake(t *testing.T) error {
	t.Helper()

	conn, err := tls.Dial("tcp", h.addr, h.clientCfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		return err
	}

	var buf [1]byte
	if _, err := conn.Read(buf[:]); err != nil {
		return err
	}

	return nil
}

// serverVerdict returns the server's verdict on the most recent handshake.
func (h *revocationHarness) serverVerdict(t *testing.T) error {
	t.Helper()

	select {
	case err := <-h.serverErrs:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the server never reported a handshake verdict")

		return nil
	}
}

// drainVerdicts discards verdicts from earlier handshakes so a later
// assertion reads the one it means.
func (h *revocationHarness) drainVerdicts() {
	for {
		select {
		case <-h.serverErrs:
		default:
			return
		}
	}
}

// TestRevocationSetTakesEffectWithoutRestart is the behaviour this whole
// phase exists for: `ca revoke` has to reach a running relay.
func TestRevocationSetTakesEffectWithoutRestart(t *testing.T) {
	t.Parallel()

	h := newRevocationHarness(t, nil)

	if err := h.handshake(t); err != nil {
		t.Fatalf("an unrevoked client was refused: %v", err)
	}
	h.drainVerdicts()

	h.revoked.Replace(map[string]struct{}{h.serial: {}})

	if err := h.handshake(t); err == nil {
		t.Fatal("a revoked client was accepted after the set was swapped")
	}
	serverErr := h.serverVerdict(t)
	if serverErr == nil || !strings.Contains(serverErr.Error(), "revoked") {
		t.Fatalf("server refused for the wrong reason: %v", serverErr)
	}
	if !strings.Contains(serverErr.Error(), h.serial) {
		t.Fatalf("the refusal did not name the serial: %v", serverErr)
	}

	// And back again: the set is a handle, not a latch.
	h.revoked.Replace(nil)
	if err := h.handshake(t); err != nil {
		t.Fatalf("client still refused after being un-revoked: %v", err)
	}
}

// TestEmptyStartingSetCanStillRevoke is the regression the unconditional-hook
// decision exists to prevent.
//
// Installing VerifyPeerCertificate only when the startup set was non-empty
// meant a relay started without a CRL could never gain one: the hook it would
// need was never wired up, and a [tls.Config]'s callbacks cannot be changed once
// the listener is live. Nothing would have reported this - handshakes would
// simply keep succeeding.
func TestEmptyStartingSetCanStillRevoke(t *testing.T) {
	t.Parallel()

	for _, startWith := range []map[string]struct{}{nil, {}} {
		h := newRevocationHarness(t, startWith)

		if err := h.handshake(t); err != nil {
			t.Fatalf("an unrevoked client was refused: %v", err)
		}

		h.revoked.Replace(map[string]struct{}{h.serial: {}})
		if err := h.handshake(t); err == nil {
			t.Fatal("a relay that started with an empty CRL could not gain one")
		}
	}
}

// TestRevocationSetSemantics covers the handle itself, including the zero
// value - documented as a usable empty set, which the nil-map paths rely on.
func TestRevocationSetSemantics(t *testing.T) {
	t.Parallel()

	var zero mtls.RevocationSet
	if zero.Len() != 0 || zero.Contains("anything") {
		t.Fatal("the zero value is not an empty set")
	}

	s := mtls.NewRevocationSet(map[string]struct{}{"aa": {}, "bb": {}})
	if s.Len() != 2 || !s.Contains("aa") || s.Contains("cc") {
		t.Fatalf("set = %d entries, aa=%v cc=%v", s.Len(), s.Contains("aa"), s.Contains("cc"))
	}

	// Replace must copy: a caller mutating the map it passed in must not
	// silently change what the listener enforces.
	source := map[string]struct{}{"dd": {}}
	s.Replace(source)
	source["ee"] = struct{}{}
	if s.Contains("ee") {
		t.Fatal("Replace aliased the caller's map instead of copying it")
	}
	if !s.Contains("dd") || s.Contains("aa") {
		t.Fatal("Replace did not swap the set wholesale")
	}
}

// TestRevocationSetConcurrentAccess gives the race detector a shot at the
// handle: handshakes read it while an operator's reload writes it.
func TestRevocationSetConcurrentAccess(t *testing.T) {
	t.Parallel()

	s := mtls.NewRevocationSet(nil)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := range 1000 {
			if i%2 == 0 {
				s.Replace(map[string]struct{}{"aa": {}})
				continue
			}
			s.Replace(nil)
		}
	}()

	for range 1000 {
		s.Contains("aa")
		s.Len()
	}
	<-done
}

// TestClientConfigIgnoresRevocation pins that the check is server-side only.
// A dialing share or listen has no revocation list and must not grow one: a
// relay's own certificate is not revoked out from under a client mid-flow the
// way a client's can be by its operator.
func TestClientConfigIgnoresRevocation(t *testing.T) {
	t.Parallel()

	rootBundle, err := ca.Init("client config root", ca.DefaultCAValidity)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.Load(rootBundle.CertPEM, rootBundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := root.Issue(ca.IssueRequest{CommonName: "node", Validity: ca.DefaultDeviceValidity})
	if err != nil {
		t.Fatal(err)
	}

	dir := bundleDir(t, bundle, root.CertPEM)
	revoked := mtls.NewRevocationSet(map[string]struct{}{
		bundle.Cert.SerialNumber.Text(ca.SerialTextBase): {},
	})

	cfg, err := mtls.LoadConfig(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "ca.pem"), false, revoked)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Fatal("a client config installed a revocation check")
	}
}

// TestServerConfigDisablesSessionTickets pins a decision two separate checks
// now depend on. A resumed TLS 1.3 connection skips the client Certificate
// message, so neither the revocation check nor the admin role check would see
// a leaf to inspect - and both would silently pass.
func TestServerConfigDisablesSessionTickets(t *testing.T) {
	t.Parallel()

	h := newRevocationHarness(t, nil)
	if err := h.handshake(t); err != nil {
		t.Fatalf("harness handshake failed: %v", err)
	}

	rootBundle, err := ca.Init("ticket test root", ca.DefaultCAValidity)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.Load(rootBundle.CertPEM, rootBundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := root.Issue(ca.IssueRequest{
		CommonName: "relay", Validity: ca.DefaultDeviceValidity, Server: true,
		IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := bundleDir(t, bundle, root.CertPEM)
	cfg, err := mtls.LoadConfig(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "ca.pem"), true, mtls.NewRevocationSet(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("a server config allowed session resumption, which would skip both post-handshake checks")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("a server config with an empty set installed no revocation hook, so it could never gain one")
	}
}
