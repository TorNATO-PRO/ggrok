package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeCredentials reserves every destination before writing any credential.
// Exclusive creation refuses existing files and symlinks, prevents concurrent
// issuers from clobbering each other, and guarantees newly created keys use
// private permissions. Callers must use an output directory they control.
func writeCredentials(dir string, contents map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	files := make(map[string]*os.File, len(contents))
	complete := false
	defer func() {
		for name, f := range files {
			_ = f.Close()
			if !complete {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}()

	for name := range contents {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("reserve credential %s (use a fresh output directory): %w", name, err)
		}
		files[name] = f
	}
	for name, f := range files {
		if _, err := f.Write(contents[name]); err != nil {
			return fmt.Errorf("write credential %s: %w", name, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close credential %s: %w", name, err)
		}
	}
	complete = true
	return nil
}
