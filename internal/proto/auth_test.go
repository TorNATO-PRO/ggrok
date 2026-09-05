package proto_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
)

// recordingConn captures one direction of an authenticated exchange.
type recordingConn struct {
	net.Conn

	wire bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	_, _ = c.wire.Write(p[:n])
	return n, err
}

func TestAuthenticatedTunnel(t *testing.T) {
	t.Parallel()
	for _, mismatch := range []string{"none", "token", "port"} {
		t.Run(mismatch, func(t *testing.T) {
			t.Parallel()
			checkAuthenticatedTunnel(t, mismatch)
		})
	}
}

func checkAuthenticatedTunnel(t *testing.T, mismatch string) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	creds := newCredentials(t)
	// The subscriber joins with what share would actually have handed it,
	// so the round trip through a subscriber token is on the tested path.
	other := creds.SubscriberToken().Credentials()
	var port proto.PortIndex
	if mismatch == "token" {
		other = newCredentials(t)
	}
	if mismatch == "port" {
		port = 1
	}
	result := make(chan error, 1)
	go func() { result <- sendGreeting(a, creds) }()
	sub, err := proto.NewAuthenticatedConn(b, other, proto.RoleSubscribe, port)
	if mismatch != "none" {
		_ = b.Close()
		if err == nil || <-result == nil {
			t.Fatal("unauthorized tunnel accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(sub)
	if err != nil || string(got) != "service greeting" {
		t.Fatalf("greeting = %q, error = %v", got, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func sendGreeting(conn net.Conn, creds proto.Credentials) error {
	defer conn.Close()
	pub, err := proto.NewAuthenticatedConn(conn, creds, proto.RolePublish, 0)
	if err != nil {
		return err
	}
	_, err = pub.Write([]byte("service greeting"))
	return err
}

func TestWholeConnectionReplayRejected(t *testing.T) {
	t.Parallel()
	creds := newCredentials(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	pubWire, subWire := &recordingConn{Conn: a}, &recordingConn{Conn: b}
	result := make(chan error, 1)
	go func() {
		_, err := proto.NewAuthenticatedConn(pubWire, creds, proto.RolePublish, 0)
		result <- err
	}()
	if _, err := proto.NewAuthenticatedConn(subWire, creds, proto.RoleSubscribe, 0); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}

	// A relay knows the complete transcript and can replay either direction.
	// A fresh challenge from the recipient must invalidate the recorded proof.
	for _, replay := range []struct {
		role proto.Role
		wire []byte
	}{
		{proto.RolePublish, subWire.wire.Bytes()},
		{proto.RoleSubscribe, pubWire.wire.Bytes()},
	} {
		conn := source{bytes.NewReader(replay.wire)}
		if _, err := proto.NewAuthenticatedConn(conn, creds, replay.role, 0); err == nil {
			t.Fatal("recorded connection authenticated against a fresh challenge")
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestEncryptedWriteFailureIsPermanent(t *testing.T) {
	t.Parallel()
	conn, err := proto.NewEncryptedConn(sink{shortWriter{}}, newSecret(t), proto.RolePublish)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if n, err := conn.Write([]byte("message")); n != 0 || err == nil {
			t.Fatalf("short write returned (%d, %v)", n, err)
		}
	}
}

type replaceableReader struct {
	net.Conn

	replay io.Reader
}

func (c *replaceableReader) Read(p []byte) (int, error) {
	if c.replay != nil {
		return c.replay.Read(p)
	}
	return c.Conn.Read(p)
}

func TestCiphertextCannotMoveBetweenAuthenticatedStreams(t *testing.T) {
	t.Parallel()
	creds := newCredentials(t)
	var captured []byte
	for attempt := range 2 {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		_ = a.SetDeadline(time.Now().Add(3 * time.Second))
		_ = b.SetDeadline(time.Now().Add(3 * time.Second))
		writer := &recordingConn{Conn: a}
		reader := &replaceableReader{Conn: b}
		result := make(chan *proto.EncryptedConn, 1)
		go func() {
			pub, err := proto.NewAuthenticatedConn(writer, creds, proto.RolePublish, 0)
			if err != nil {
				t.Error(err)
			}
			result <- pub
		}()
		sub, err := proto.NewAuthenticatedConn(reader, creds, proto.RoleSubscribe, 0)
		if err != nil {
			t.Fatal(err)
		}
		pub := <-result
		if pub == nil {
			t.Fatal("publisher handshake failed")
		}
		if attempt == 1 {
			reader.replay = bytes.NewReader(captured)
			if _, err := sub.Read(make([]byte, 4)); err == nil {
				t.Fatal("ciphertext from another authenticated stream was accepted")
			}
			return
		}
		writer.wire.Reset()
		done := make(chan error, 1)
		go func() {
			_, err := pub.Write([]byte("ping"))
			done <- err
		}()
		if _, err := io.ReadFull(sub, make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		captured = bytes.Clone(writer.wire.Bytes())
	}
}
