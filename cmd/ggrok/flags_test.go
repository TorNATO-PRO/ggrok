package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
)

// connFlags returns the -server/-cert-file/-key-file/-ca-file every share and
// listen invocation needs, pointed at placeholder files. Nothing here dials
// anything, so the certificates only have to exist.
func connFlags(t *testing.T) []string {
	t.Helper()

	dir := t.TempDir()
	for _, name := range []string{"cert.pem", "key.pem", "ca.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return []string{
		"-cert-file", filepath.Join(dir, "cert.pem"),
		"-key-file", filepath.Join(dir, "key.pem"),
		"-ca-file", filepath.Join(dir, "ca.pem"),
		"-server", "127.0.0.1:4443",
	}
}

// testSession returns a session key and the subscriber token derived from it.
func testSession(t *testing.T) (proto.SessionKey, proto.SubscriberToken) {
	t.Helper()

	key, err := proto.NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}

	creds, err := key.Credentials()
	if err != nil {
		t.Fatal(err)
	}

	return key, creds.SubscriberToken()
}

// TestShareFlagSetIsWellFormed parses a minimal share invocation.
//
// [flag.FlagSet] panics on a redefined name, and it does so at parse time - so
// a second flag accidentally registered under a name registerConnFlags already
// uses is not a compile error, not a vet finding, and not visible in any test
// that never builds the flag set. It is a panic on every single run of the
// command. Registering the session key as -key-file did exactly that,
// colliding with this node's TLS private key.
func TestShareFlagSetIsWellFormed(t *testing.T) {
	t.Parallel()

	key, _ := testSession(t)
	args := append([]string{"-tcp", "127.0.0.1:8080", "-session-key", key.String()}, connFlags(t)...)

	cfg, err := parseShareFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sessionKey == nil || *cfg.sessionKey != key {
		t.Fatal("share did not take the session key it was given")
	}
}

func TestShareReadsTheSessionKeyFromAFile(t *testing.T) {
	t.Parallel()

	key, _ := testSession(t)
	path := filepath.Join(t.TempDir(), "session.key")
	if err := os.WriteFile(path, []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args := append([]string{"-tcp", "127.0.0.1:8080", "-session-key-file", path}, connFlags(t)...)

	cfg, err := parseShareFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sessionKey == nil || *cfg.sessionKey != key {
		t.Fatal("share did not read the session key from -session-key-file")
	}
}

// TestListenFlagSetIsWellFormed is TestShareFlagSetIsWellFormed for listen.
func TestListenFlagSetIsWellFormed(t *testing.T) {
	t.Parallel()

	_, token := testSession(t)
	args := append([]string{"-tcp", "127.0.0.1:9090", "-token", token.String()}, connFlags(t)...)

	cfg, err := parseListenFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.token != token {
		t.Fatal("listen did not take the token it was given")
	}
}

func TestListenReadsTheTokenFromAFile(t *testing.T) {
	t.Parallel()

	_, token := testSession(t)
	path := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(path, []byte(token.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args := append([]string{"-tcp", "127.0.0.1:9090", "-token-file", path}, connFlags(t)...)

	cfg, err := parseListenFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.token != token {
		t.Fatal("listen did not read the token from -token-file")
	}
}

// TestTheTwoSecretsDoNotCrossOver covers the mistake someone actually makes.
// Both values are base32 of the same alphabet and differ only in length, so
// pasting the one you hand out where the one you keep belongs has to fail
// loudly rather than half-work.
func TestTheTwoSecretsDoNotCrossOver(t *testing.T) {
	t.Parallel()

	key, token := testSession(t)

	shareArgs := append([]string{"-tcp", "127.0.0.1:8080", "-session-key", token.String()}, connFlags(t)...)
	if _, err := parseShareFlags(shareArgs); err == nil {
		t.Error("share accepted a subscriber token as a session key")
	}

	listenArgs := append([]string{"-tcp", "127.0.0.1:9090", "-token", key.String()}, connFlags(t)...)
	err := parseListenTokenErr(t, listenArgs)
	if err == nil {
		t.Fatal("listen accepted a session key as a subscriber token")
	}
	if !strings.Contains(err.Error(), "subscriber token") {
		t.Errorf("error does not name what was wrong: %v", err)
	}
}

func parseListenTokenErr(t *testing.T, args []string) error {
	t.Helper()

	_, err := parseListenFlags(args)
	return err
}

// TestReportTokenRefusesNonTerminalStdout pins the gate on the printed token.
// Test binaries run with stdout redirected, so this exercises the refusing
// path by construction - which is the point: a share whose stdout is not a
// terminal is a share whose token is about to land in something durable.
func TestReportTokenRefusesNonTerminalStdout(t *testing.T) {
	t.Parallel()

	_, token := testSession(t)

	if err := reportToken(shareConfig{}, token); err == nil {
		t.Fatal("the token was printed to a non-terminal stdout")
	}

	// -token-out is the way through, and it must land 0600.
	path := filepath.Join(t.TempDir(), "token.txt")
	if err := reportToken(shareConfig{tokenOut: path}, token); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode = %04o, want 0600", perm)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := proto.ParseSubscriberToken(strings.TrimSpace(string(written)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != token {
		t.Fatal("the token written to -token-out is not this session's")
	}
}
