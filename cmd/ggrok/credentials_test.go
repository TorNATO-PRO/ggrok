package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialsRefuseExistingKey(t *testing.T) {
	t.Parallel()
	for _, symlink := range []bool{false, true} {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "original")
		if err := os.WriteFile(target, []byte("original key"), 0o644); err != nil {
			t.Fatal(err)
		}
		key := filepath.Join(dir, "key.pem")
		if symlink {
			if err := os.Symlink(target, key); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(key, []byte("original key"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := writeCredentials(dir, map[string][]byte{
			"cert.pem": []byte("new certificate"), "key.pem": []byte("new secret"),
		}); err == nil {
			t.Fatal("existing key was accepted")
		}
		got, err := os.ReadFile(key)
		if err != nil || string(got) != "original key" {
			t.Fatalf("existing key changed: %q, %v", got, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "cert.pem")); !os.IsNotExist(err) {
			t.Fatalf("failed bundle left a certificate behind: %v", err)
		}
	}
}

func TestCredentialsPrivatePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := writeCredentials(dir, map[string][]byte{"key.pem": []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}
}
