package udpcrypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/udpcrypto"
)

// replayWindowSize mirrors udpcrypto's unexported constant of the same
// name, duplicated here since this black-box test package can't see it
// directly - see TestReplayWindowRejectsTooOld/TestReplayWindowAdvances.
const replayWindowSize = 64

// tlsConnPair returns the two ends of an in-memory TLS 1.3 connection,
// already handshaken, for exercising DeriveKey against real
// [tls.ConnectionState] values without touching the filesystem or a real
// socket.
func tlsConnPair(t *testing.T) (*tls.Conn, *tls.Conn) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	serverConn, clientConn := net.Pipe()

	serverTLS := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true, // test-only self-signed pair, not real mTLS - gosec doesn't lint _test.go files
		MinVersion:         tls.VersionTLS13,
	})

	handshakeErr := make(chan error, 2)
	go func() { handshakeErr <- serverTLS.Handshake() }()
	go func() { handshakeErr <- clientTLS.Handshake() }()

	for range 2 {
		if err := <-handshakeErr; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}

	// Deliberately not Close()d: (*tls.Conn).Close sends a close_notify
	// alert under a hardcoded 5s write deadline (see crypto/tls's
	// closeNotify), which blocks for the full 5s on this unbuffered
	// net.Pipe since nothing reads after the handshake. net.Pipe holds no
	// real OS resource, so there's nothing to leak by skipping Close here.

	return clientTLS, serverTLS
}

func TestDeriveKeyMatchesAcrossConnectionEnds(t *testing.T) {
	t.Parallel()
	client, server := tlsConnPair(t)

	routing, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}
	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	clientState := client.ConnectionState()
	serverState := server.ConnectionState()

	clientKey, err := udpcrypto.DeriveKey(&clientState, routing, token, udpcrypto.DirectionUplink)
	if err != nil {
		t.Fatalf("client DeriveKey: %v", err)
	}
	serverKey, err := udpcrypto.DeriveKey(&serverState, routing, token, udpcrypto.DirectionUplink)
	if err != nil {
		t.Fatalf("server DeriveKey: %v", err)
	}

	if clientKey != serverKey {
		t.Error("DeriveKey produced different keys on the two ends of the same TLS connection")
	}
}

func TestDeriveKeyDiffersByDirection(t *testing.T) {
	t.Parallel()
	client, _ := tlsConnPair(t)
	state := client.ConnectionState()

	routing, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}
	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	up, err := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionUplink)
	if err != nil {
		t.Fatal(err)
	}
	down, err := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionDownlink)
	if err != nil {
		t.Fatal(err)
	}

	if up == down {
		t.Error("DeriveKey produced the same key for both directions")
	}
}

func TestDeriveKeyDiffersByRoutingID(t *testing.T) {
	t.Parallel()
	client, _ := tlsConnPair(t)
	state := client.ConnectionState()

	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	r1, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}
	r2, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}

	k1, err := udpcrypto.DeriveKey(&state, r1, token, udpcrypto.DirectionUplink)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := udpcrypto.DeriveKey(&state, r2, token, udpcrypto.DirectionUplink)
	if err != nil {
		t.Fatal(err)
	}

	if k1 == k2 {
		t.Error("DeriveKey produced the same key for two different routing IDs")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	client, server := tlsConnPair(t)
	routing, err := proto.NewRoutingID()
	if err != nil {
		t.Fatal(err)
	}
	token, err := proto.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	clientState := client.ConnectionState()
	serverState := server.ConnectionState()

	sendKey, err := udpcrypto.DeriveKey(&clientState, routing, token, udpcrypto.DirectionUplink)
	if err != nil {
		t.Fatal(err)
	}
	recvKey, err := udpcrypto.DeriveKey(&serverState, routing, token, udpcrypto.DirectionUplink)
	if err != nil {
		t.Fatal(err)
	}

	sendAEAD, err := udpcrypto.NewAEAD(sendKey)
	if err != nil {
		t.Fatal(err)
	}
	recvAEAD, err := udpcrypto.NewAEAD(recvKey)
	if err != nil {
		t.Fatal(err)
	}

	var window udpcrypto.ReplayWindow
	want := []byte("hello from the other side")

	datagram := udpcrypto.Seal(sendAEAD, routing, 0, want)

	got, err := udpcrypto.Open(recvAEAD, &window, datagram)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()

	client, server := tlsConnPair(t)
	routing, _ := proto.NewRoutingID()
	token, _ := proto.NewToken()
	clientState := client.ConnectionState()
	serverState := server.ConnectionState()

	sendKey, _ := udpcrypto.DeriveKey(&clientState, routing, token, udpcrypto.DirectionUplink)
	recvKey, _ := udpcrypto.DeriveKey(&serverState, routing, token, udpcrypto.DirectionUplink)
	sendAEAD, _ := udpcrypto.NewAEAD(sendKey)
	recvAEAD, _ := udpcrypto.NewAEAD(recvKey)

	var window udpcrypto.ReplayWindow
	datagram := udpcrypto.Seal(sendAEAD, routing, 0, []byte("payload"))
	datagram[len(datagram)-1] ^= 0xff // flip a bit in the ciphertext/tag

	if _, err := udpcrypto.Open(recvAEAD, &window, datagram); err == nil {
		t.Error("expected error opening tampered datagram, got nil")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	t.Parallel()

	client, _ := tlsConnPair(t)
	routing, _ := proto.NewRoutingID()
	token, _ := proto.NewToken()
	state := client.ConnectionState()

	sendKey, _ := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionUplink)
	// deliberately the wrong key: same inputs, wrong direction
	wrongKey, _ := udpcrypto.DeriveKey(&state, routing, token, udpcrypto.DirectionDownlink)
	sendAEAD, _ := udpcrypto.NewAEAD(sendKey)
	wrongAEAD, _ := udpcrypto.NewAEAD(wrongKey)

	var window udpcrypto.ReplayWindow
	datagram := udpcrypto.Seal(sendAEAD, routing, 0, []byte("payload"))

	if _, err := udpcrypto.Open(wrongAEAD, &window, datagram); err == nil {
		t.Error("expected error opening with the wrong key, got nil")
	}
}

func TestReplayWindowRejectsDuplicate(t *testing.T) {
	t.Parallel()

	var w udpcrypto.ReplayWindow

	if w.Seen(5) {
		t.Fatal("first-ever counter reported as already seen")
	}
	w.Mark(5)

	if !w.Seen(5) {
		t.Error("duplicate counter not detected as seen")
	}
}

func TestReplayWindowAcceptsReordering(t *testing.T) {
	t.Parallel()

	var w udpcrypto.ReplayWindow

	for _, c := range []uint64{10, 12, 11} { // 11 arrives out of order after 12
		if w.Seen(c) {
			t.Fatalf("counter %d reported as seen before being marked", c)
		}
		w.Mark(c)
	}

	for _, c := range []uint64{10, 11, 12} {
		if !w.Seen(c) {
			t.Errorf("counter %d not detected as seen after being marked", c)
		}
	}
}

func TestReplayWindowRejectsTooOld(t *testing.T) {
	t.Parallel()

	var w udpcrypto.ReplayWindow

	w.Mark(1000)

	if !w.Seen(1000 - replayWindowSize) {
		t.Error("counter exactly replayWindowSize behind highest should be rejected as too old")
	}
	if w.Seen(1000 - replayWindowSize + 1) {
		t.Error("counter just inside the window should not be rejected as too old")
	}
}

func TestReplayWindowAdvances(t *testing.T) {
	t.Parallel()

	var w udpcrypto.ReplayWindow

	w.Mark(0)
	w.Mark(1000) // far ahead - the whole old window should fall out the back

	if !w.Seen(0) {
		t.Error("counter 0 should now be too old to trust")
	}
	if w.Seen(1001) {
		t.Error("a counter ahead of the new highest should not be reported as already seen")
	}
}

func TestSessionSendRecvRoundTrip(t *testing.T) {
	t.Parallel()

	client, server := tlsConnPair(t)
	routing, _ := proto.NewRoutingID()
	token, _ := proto.NewToken()
	clientState := client.ConnectionState()
	serverState := server.ConnectionState()

	clientSend, _ := udpcrypto.DeriveKey(&clientState, routing, token, udpcrypto.DirectionUplink)
	serverRecv, _ := udpcrypto.DeriveKey(&serverState, routing, token, udpcrypto.DirectionUplink)

	a, b := net.Pipe()
	clientSession, err := udpcrypto.NewSession(a, routing, clientSend, [udpcrypto.KeySize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	serverSession, err := udpcrypto.NewSession(b, routing, [udpcrypto.KeySize]byte{}, serverRecv)
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("udp mode payload")
	sendErr := make(chan error, 1)
	go func() { sendErr <- clientSession.Send(want) }()

	buf := make([]byte, 2048)
	got, err := serverSession.Recv(buf)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
