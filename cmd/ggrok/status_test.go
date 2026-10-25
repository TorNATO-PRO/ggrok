package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
)

func TestFailedShareDoesNotEmitToken(t *testing.T) {
	t.Parallel()
	key, _ := testSession(t)
	server, err := hostport.Parse("127.0.0.1:4443")
	if err != nil {
		t.Fatal(err)
	}
	addr, err := hostport.ParseRange("127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "token.txt")
	cfg := shareConfig{
		addr:       addr,
		sessionKey: &key,
		tokenOut:   output,
		server:     server,
		certFile:   filepath.Join(t.TempDir(), "missing.pem"),
	}
	if err := runShare(cfg); err == nil {
		t.Fatal("share succeeded without credentials")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token emitted before successful registration: %v", err)
	}
}

func TestListenWaitFlag(t *testing.T) {
	t.Parallel()
	_, token := testSession(t)
	for _, flag := range []string{"--wait", "-wait"} {
		args := append([]string{"--tcp", "127.0.0.1:0", "--token", token.String(), flag}, connFlags(t)...)
		cfg, err := parseListenFlags(args)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.wait {
			t.Fatal("wait flag not applied")
		}
	}
}

func TestSessionErrorHintsPreserveCause(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		err  error
		hint string
	}{
		{proto.ErrNoSuchSession, "listen --wait"},
		{proto.ErrPortsMismatch, "same number of ports"},
		{context.Canceled, "canceled"},
	} {
		got := explainSessionError(tt.err)
		if !errors.Is(got, tt.err) || !strings.Contains(got.Error(), tt.hint) {
			t.Errorf("explainSessionError: %v", got)
		}
	}
	if err := explainSessionError(nil); err != nil {
		t.Fatal(err)
	}
}

func TestForwardErrorsAreBoundedAndSanitized(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	reporter := forwardErrorReporter{out: &output}
	now := time.Now()
	reporter.report(errors.New("service down\nforged line\x1b[2J"), now)
	const failures = 50
	var wg sync.WaitGroup
	for range failures {
		wg.Go(func() { reporter.report(errors.New("service down"), now) })
	}
	wg.Wait()
	if strings.Count(output.String(), "\n") != 1 || strings.Contains(output.String(), "\x1b[2J") {
		t.Fatalf("unbounded or unsafe output: %q", output.String())
	}
	reporter.report(errors.New("service still down"), now.Add(forwardErrorInterval))
	if !strings.Contains(output.String(), "50 additional failures suppressed") {
		t.Fatalf("missing summary: %q", output.String())
	}
	if strings.Count(output.String(), "\n") != 2 {
		t.Fatalf("wrong output count: %q", output.String())
	}
}
