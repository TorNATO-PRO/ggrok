// config.go holds the flag/config-file plumbing shared by every CLI
// command that dials relay as an mTLS peer: share and listen. Both
// resolve their relay address, certificate, key, and CA through the same
// precedence chain (flag > env var > configDir's config.json > a
// well-known default path inside configDir for cert/key/ca), so it lives
// in one place instead of twice.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	hostport "tornato.dev/ggrok/v2/internal"
)

// nodeConnConfig is the relay connection info shared by share and listen.
type nodeConnConfig struct {
	// server denotes the relay service host:port pair
	// where the host may either be an IP or a DNS name
	server hostport.HostPort

	// certFile is the path to node's own certificate file, which
	// provides the public key and identity. In plain English,
	// this is ggrok saying "I am the client X". For a server, we would
	// be saying something like "I am the ggrok rely server at someserver.xyz"
	certFile string

	// keyFile is the path to this node's private key, which is paired
	// with a certfile. We use this to sign and decrypt things during the TLS
	// handshake, and it helps to prove we are not just presenting someone else's
	// cert because you hold the private key. This file must NEVER under any
	// circumstances leave the machine it was provisioned on or be world readable (mode 600).
	keyFile string

	// caFile is the path to the Certificate Authority cert used to verify the peer's
	// certificate. In a normal TLS setup, your OS ships a huge big bundle of public CAs
	// from sources like Let's Encrypt, DigiCert, etc... and you don't need to specify this.
	// In our case, we are doing mTLS with a private CA. We are not getting a peer cert signed
	// by a public CA for a relay/client pair. The caFile instead points to your own self-signed
	// root cert, and both sides use it to check "was the peer's cert signed by my CA?" instead of
	// trusting the public web PKI. Its a bit inconvenient but it helps us make mTLS work.
	caFile string
}

// nodeFileConfig mirrors the on-disk JSON config at configDir/config.json.
// Any field left blank defers to that setting's environment variable or
// built-in default instead.
type nodeFileConfig struct {
	Server   string `json:"server"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}

// loadNodeFileConfig reads configDir/config.json if it exists. A missing
// file is not an error - it just means every setting falls through to its
// environment variable or built-in default.
func loadNodeFileConfig(configDir string) (nodeFileConfig, error) {
	path := filepath.Join(configDir, "config.json")
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nodeFileConfig{}, nil
	case err != nil:
		return nodeFileConfig{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg nodeFileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nodeFileConfig{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	return cfg, nil
}

// firstNonEmpty returns the first non-empty string in vals. Callers pass
// arguments in precedence order - env var, then config file, then a
// built-in default - so whichever source is actually set wins.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}

	return ""
}

// expandHome replaces a leading "~" or "~/" in path with the current
// user's home directory. Go's os package has no notion of "~" - that's
// shell syntax the shell itself expands before argv ever reaches us - so
// a path arriving through config.json or a GGROK_*_FILE env var (which no
// shell ever touches) needs this done explicitly, or an entirely
// reasonable-looking "~/.ggrok/cert.pem" silently resolves to a literal
// "~" subdirectory of wherever the process happens to be running from.
func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand %s: %w", path, err)
	}

	if path == "~" {
		return home, nil
	}

	return filepath.Join(home, path[len("~/"):]), nil
}

// expandHomeInto expands *path via expandHome and writes the result back
// in place - the common shape every path-shaped flag/config value needs.
func expandHomeInto(path *string) error {
	expanded, err := expandHome(*path)
	if err != nil {
		return err
	}

	*path = expanded
	return nil
}

// defaultConfigDir returns ~/.ggrok, the directory share and listen read
// their config.json and default cert/key/ca from.
func defaultConfigDir() (string, error) {
	// I find it really cool that Go makes something like this
	// with sane defaults for every operating system. Makes cross
	// compilation a breeze. It's the little things
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".ggrok"), nil
}

// registerConnFlags resolves connection settings only when the command runs,
// so help and completion do not depend on local credentials or valid config.
func registerConnFlags(fs *pflag.FlagSet, cfg *nodeConnConfig) func() error {
	var server string
	fs.StringVar(&server, "server", "", "relay address (env GGROK_SERVER)")
	fs.StringVar(&cfg.certFile, "cert-file", "", "node certificate (env GGROK_CERT_FILE)")
	fs.StringVar(&cfg.keyFile, "key-file", "", "node private key (env GGROK_KEY_FILE)")
	fs.StringVar(&cfg.caFile, "ca-file", "", "CA certificate (env GGROK_CA_FILE)")
	return func() error {
		configDir, err := defaultConfigDir()
		if err != nil {
			return err
		}
		fileCfg, err := loadNodeFileConfig(configDir)
		if err != nil {
			return err
		}
		for _, setting := range []struct {
			name, env, file, fallback string
			dest                      *string
		}{
			{"server", "GGROK_SERVER", fileCfg.Server, "", &server},
			{"cert-file", "GGROK_CERT_FILE", fileCfg.CertFile, filepath.Join(configDir, "cert.pem"), &cfg.certFile},
			{"key-file", "GGROK_KEY_FILE", fileCfg.KeyFile, filepath.Join(configDir, "key.pem"), &cfg.keyFile},
			{"ca-file", "GGROK_CA_FILE", fileCfg.CAFile, filepath.Join(configDir, "ca.pem"), &cfg.caFile},
		} {
			if !fs.Changed(setting.name) {
				*setting.dest = firstNonEmpty(os.Getenv(setting.env), setting.file, setting.fallback)
			}
		}
		for _, path := range []*string{&cfg.certFile, &cfg.keyFile, &cfg.caFile} {
			if err = expandHomeInto(path); err != nil {
				return err
			}
		}
		if server == "" {
			return fmt.Errorf("--server is required (flag, GGROK_SERVER, or %s)",
				filepath.Join(configDir, "config.json"))
		}
		pair, err := hostport.Parse(server)
		if err != nil {
			return fmt.Errorf("invalid server: %w", err)
		}
		cfg.server = pair
		return nil
	}
}
