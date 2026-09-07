package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

//nolint:paralleltest // Help must remain independent of process-wide config and secrets.
func TestHelpAndCompletionIgnoreBrokenConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GGROK_SESSION_KEY", "private-session-key")
	t.Setenv("GGROK_TOKEN", "private-subscriber-token")
	dir := filepath.Join(home, ".ggrok")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("broken JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{},
		{"--help"},
		{"help", "share"},
		{"share", "-h"},
		{"listen", "-help"},
		{"relay", "--help"},
		{"ca", "--help"},
		{"ca", "init", "--help"},
		{"ca", "issue", "--help"},
		{"ca", "list", "--help"},
		{"ca", "revoke", "--help"},
		{"ca", "crl", "--help"},
		{"admin", "--help"},
		{"admin", "ls", "--help"},
		{"admin", "kick", "--help"},
		{"admin", "reload-crl", "--help"},
		{"completion", "bash"},
		{"completion", "zsh"},
		{"completion", "fish"},
		{"completion", "powershell"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := newRootCommand()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			if err := executeCommand(cmd, args); err != nil {
				t.Fatal(err)
			}
			if output.Len() == 0 {
				t.Fatal("no help or completion output")
			}
			for _, secret := range []string{"private-session-key", "private-subscriber-token"} {
				if strings.Contains(output.String(), secret) {
					t.Fatal("secret leaked into help")
				}
			}
			if reflect.DeepEqual(args, []string{"ca", "--help"}) && !strings.Contains(output.String(), "crl") {
				t.Fatal("generated help omitted ca crl")
			}
		})
	}
}

func TestLegacyFlagNormalization(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ args, want []string }{
		{[]string{"share", "-tcp", "127.0.0.1:80", "-server=localhost:4443"}, []string{"share", "--tcp", "127.0.0.1:80", "--server=localhost:4443"}},
		{[]string{"ca", "issue", "-server", "-common-name", "-server", "-admin=false"}, []string{"ca", "issue", "--server", "--common-name", "-server", "--admin=false"}},
		{[]string{"listen", "-token-file", "-", "--", "-token"}, []string{"listen", "--token-file", "-", "--", "-token"}},
		{[]string{"-color", "ca", "crl", "-out", "-color"}, []string{"--color", "ca", "crl", "--out", "-color"}},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			t.Parallel()
			got := normalizeLegacyFlags(newRootCommand(), tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnectionConfigPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, name := range []string{"GGROK_SERVER", "GGROK_CERT_FILE", "GGROK_KEY_FILE", "GGROK_CA_FILE"} {
		t.Setenv(name, "")
	}
	dir := filepath.Join(home, ".ggrok")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"server":"localhost:4443","cert_file":"~/file.pem"}`)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, env, want string
		extra           []string
	}{
		{name: "file", want: filepath.Join(home, "file.pem")},
		{name: "environment", env: "~/env.pem", want: filepath.Join(home, "env.pem")},
		{name: "flag", env: "~/env.pem", extra: []string{"--cert-file", "~/flag.pem"}, want: filepath.Join(home, "flag.pem")},
		{name: "explicit empty flag", env: "~/env.pem", extra: []string{"--cert-file="}, want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GGROK_CERT_FILE", tt.env)
			cfg, err := parseShareFlags(append([]string{"--tcp", "127.0.0.1:8080"}, tt.extra...))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.certFile != tt.want {
				t.Fatalf("cert = %q, want %q", cfg.certFile, tt.want)
			}
			if cfg.keyFile != filepath.Join(dir, "key.pem") {
				t.Fatalf("wrong default key: %s", cfg.keyFile)
			}
		})
	}
}

func TestCobraRejectsInvalidInputBeforeExecution(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"share", "--not-a-flag"},
		{"share", "--tcp"},
		{"share", "unexpected"},
		{"ca", "issue", "unexpected"},
		{"admin", "kick", "unexpected"},
		{"listen", "one", "two"},
		{"ca", "bogus"},
		{"admin", "bogus"},
		{"bogus"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			if err := executeCommand(newRootCommand(), args); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	cmd := newRootCommand()
	if err := executeCommand(cmd, []string{"share", "--not-a-flag"}); !errors.Is(err, errUsage) {
		t.Fatalf("wrong error category: %v", err)
	}
}

func TestListenAcceptsFlagsAfterPositionalToken(t *testing.T) {
	t.Parallel()
	_, token := testSession(t)
	args := append([]string{token.String(), "--tcp", "127.0.0.1:8080"}, connFlags(t)...)
	cfg, err := parseListenFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.token != token {
		t.Fatal("wrong token")
	}
}

func TestCAIssueParsesLegacyBooleanAndRepeatedFlags(t *testing.T) {
	t.Parallel()
	cmd := newCAIssueCommand()
	cmd.RunE = func(*cobra.Command, []string) error { return nil }
	args := []string{"-server", "-admin", "-dns-name", "a.example", "-dns-name", "b.example", "-ip", "127.0.0.1"}
	if err := executeCommand(cmd, args); err != nil {
		t.Fatal(err)
	}
	server, err := cmd.Flags().GetBool("server")
	if err != nil || !server {
		t.Fatalf("server=%v, err=%v", server, err)
	}
}
