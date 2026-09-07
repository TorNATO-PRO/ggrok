// secrets.go holds how share and listen take a session secret in and give
// one back. Both are exposure problems rather than parsing ones.
//
// A secret on the command line is visible to every local user through ps and
// is persisted in shell history. An environment variable is better but not
// clean: it's readable through /proc/<pid>/environ, inherited by every child
// process, and exposed by ps e on some systems. A file is the only channel
// here with no ambient exposure and real permissions, which is why
// -session-key-file and -token-file are the documented path and everything
// else is a fallback.
//
// The same reasoning runs in the other direction. share's subscriber token
// went to stdout unconditionally, so it landed in scrollback, tmux logs,
// script captures, and CI job output - anywhere stdout was not a terminal it
// was being written to something durable. Printing is now gated on stdout
// being a terminal, with -token-out for everywhere else.

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// stdioPath is the value -session-key-file, -token-file, and -token-out
// accept in place of a path to mean standard input or standard output.
const stdioPath = "-"

// readSecretFile reads a secret from path, or from stdin if path is
// stdioPath. Surrounding whitespace is trimmed, so a file written with a
// trailing newline - which is to say, a file written by any ordinary means -
// parses.
func readSecretFile(path string) (string, error) {
	var reader io.Reader = os.Stdin
	if path != stdioPath {
		if err := expandHomeInto(&path); err != nil {
			return "", err
		}
		f, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		defer func() { _ = f.Close() }()
		reader = f
	}
	// Tokens are at most 52 characters; allow whitespace without accepting
	// unbounded input from a file, device, or pipe.
	const maxSecretBytes = 4096
	data, err := io.ReadAll(io.LimitReader(reader, maxSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	if len(data) > maxSecretBytes {
		return "", fmt.Errorf("secret exceeds %d bytes", maxSecretBytes)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return secret, nil
}

// isTerminal reports whether f is a character device - a terminal someone is
// watching, rather than a file, a pipe, or a CI log. A Stat that fails is
// treated as "not a terminal", which is the safe direction for both callers:
// a secret is withheld rather than written somewhere durable on a guess, and
// escape sequences are withheld rather than written into something that will
// only store them.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

// stdoutIsTerminal reports whether stdout is a terminal, which is what gates
// printing the subscriber token.
func stdoutIsTerminal() bool {
	return isTerminal(os.Stdout)
}

// writeSecretFile writes secret plus a newline to path, or to stdout if path
// is stdioPath. A real path must be fresh and is created 0600. Existing files
// and symlinks are refused, matching credential issuance.
func writeSecretFile(path, secret string) error {
	if path == stdioPath {
		_, err := fmt.Fprintln(os.Stdout, secret)
		return err
	}

	if err := expandHomeInto(&path); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := fmt.Fprintln(f, secret); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}

	return f.Close()
}
