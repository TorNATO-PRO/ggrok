package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretOutputRefusesExistingFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "public")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{target, link} {
		if err := writeSecretFile(path, "secret"); err == nil {
			t.Fatalf("overwrote %s", path)
		}
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "original" {
		t.Fatalf("target changed: %q, %v", data, err)
	}
	fresh := filepath.Join(dir, "fresh")
	if writeErr := writeSecretFile(fresh, "secret"); writeErr != nil {
		t.Fatal(writeErr)
	}
	info, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret permissions: %v", info.Mode())
	}
}

func TestSecretInputBound(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "token")
	for _, size := range []int{4096, 4097} {
		if err := os.WriteFile(path, []byte(strings.Repeat("x", size)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readSecretFile(path)
		if (err != nil) != (size > 4096) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}
