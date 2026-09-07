package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCRLReplacesSymlinkWithoutTouchingTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "revoked.txt")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeRevokedSerials(path, map[string]struct{}{"ff": {}, "ab": {}}); err != nil {
		t.Fatal(err)
	}
	targetData, err := os.ReadFile(target)
	if err != nil || string(targetData) != "keep" {
		t.Fatalf("symlink target changed: %q, %v", targetData, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "ab\nff\n" {
		t.Fatalf("CRL = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("CRL mode: %v", info.Mode())
	}
}

func TestCRLReadersSeeCompleteVersions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "revoked.txt")
	oldSet, newSet := map[string]struct{}{"ab": {}}, map[string]struct{}{"ab": {}, "ff": {}}
	if err := writeRevokedSerials(path, oldSet); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	go func() {
		defer close(done)
		for range 50 {
			if err := writeRevokedSerials(path, newSet); err != nil {
				t.Error(err)
				return
			}
			if err := writeRevokedSerials(path, oldSet); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "ab\n" && string(data) != "ab\nff\n" {
			t.Fatalf("partial CRL: %q", data)
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func TestCRLFailedReplacementCleansTemporaryFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := writeRevokedSerials(dir, map[string]struct{}{"ab": {}}); err == nil {
		t.Fatal("replaced directory with a CRL")
	}
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ggrok-crl-") {
			t.Fatal("failed write left a temporary CRL")
		}
	}
}
