// The share subcommand creates a QUIC connection to the relay server in which a file
// hosted on your device may be relayed to a downstream consumer. If the connection
// fails at any point, then a reconnect attempt will occur. Because the client is able
// to start from any arbitrary point to download, a reconnect or other network
// failure should not affect the contents of the file.
//
// With -udp, share instead forwards a local UDP service through the tunnel as a
// stream of datagrams, using QUIC's unreliable datagram extension (RFC 9221) so the
// forwarded traffic keeps UDP's unordered, unreliable delivery semantics rather than
// being flattened into an ordered, retransmitted stream.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
)

// shareConfig is the parsed and validated input to a share.
type shareConfig struct {
	// file is a path reference to the file which we are sharing with the world.
	file string

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

	// ttl is the time that we want to share the file in question to our relay server.
	ttl time.Duration

	// udp switches share from its default file-sharing mode into forwarding a
	// local UDP service through the tunnel as a stream of datagrams, instead
	// of streaming a file.
	udp bool
}

// shareFileConfig mirrors the on-disk JSON config at configDir/config.json.
// Any field left blank defers to that setting's environment variable or
// built-in default instead.
type shareFileConfig struct {
	Server   string `json:"server"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}

// loadShareFileConfig reads configDir/config.json if it exists. A missing
// file is not an error - it just means every setting falls through to its
// environment variable or built-in default.
func loadShareFileConfig(configDir string) (shareFileConfig, error) {
	path := filepath.Join(configDir, "config.json")
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return shareFileConfig{}, nil
	case err != nil:
		return shareFileConfig{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg shareFileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return shareFileConfig{}, fmt.Errorf("parsing %s: %w", path, err)
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

// parseShareFlags parses the flags for the share command
// into a validated shareConfig struct. It can fail, however,
// and when it does so an error is returned.
//
// server, cert-file, key-file and ca-file may each come from, in order of
// precedence: an explicit flag, an environment variable, or configDir's
// config.json. cert-file, key-file and ca-file additionally fall back to a
// well-known path inside configDir, since that's where we tell people to
// keep them; server has no such fallback and is required from one of the
// three sources.
func parseShareFlags(args []string) (shareConfig, error) {
	// I find it really cool that Go makes something like this
	// with sane defaults for every operating system. Makes cross
	// compilation a breeze. It's the little things
	home, err := os.UserHomeDir()
	if err != nil {
		return shareConfig{}, err
	}

	configDir := filepath.Join(home, ".ggrok")
	fileCfg, err := loadShareFileConfig(configDir)
	if err != nil {
		return shareConfig{}, err
	}

	fs := flag.NewFlagSet("share", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}

	var cfg shareConfig
	var serverSet bool
	fs.Func("server", "the relay server to share the data with (env GGROK_SERVER, or \"server\" in "+filepath.Join(configDir, "config.json")+")", func(hostPortPair string) error {
		pair, err := hostport.Parse(hostPortPair)
		if err != nil {
			return err
		}

		cfg.server = pair
		serverSet = true
		return nil
	})

	fs.StringVar(&cfg.certFile, "cert-file",
		firstNonEmpty(os.Getenv("GGROK_CERT_FILE"), fileCfg.CertFile, filepath.Join(configDir, "cert.pem")),
		"path to this node's certificate (env GGROK_CERT_FILE)")
	fs.StringVar(&cfg.keyFile, "key-file",
		firstNonEmpty(os.Getenv("GGROK_KEY_FILE"), fileCfg.KeyFile, filepath.Join(configDir, "key.pem")),
		"path to this node's private key (env GGROK_KEY_FILE)")
	fs.StringVar(&cfg.caFile, "ca-file",
		firstNonEmpty(os.Getenv("GGROK_CA_FILE"), fileCfg.CAFile, filepath.Join(configDir, "ca.pem")),
		"path to the CA certificate used to verify the peer (env GGROK_CA_FILE)")
	fs.BoolVar(&cfg.udp, "udp", false, "forward a UDP stream over the QUIC tunnel instead of sharing a file")

	if err := parseFlags(fs, args); err != nil {
		return shareConfig{}, err
	}

	if !serverSet {
		serverStr := firstNonEmpty(os.Getenv("GGROK_SERVER"), fileCfg.Server)
		if serverStr == "" {
			fs.Usage()
			return shareConfig{}, fmt.Errorf("-server is required (flag, GGROK_SERVER env var, or \"server\" in %s)", filepath.Join(configDir, "config.json"))
		}

		pair, err := hostport.Parse(serverStr)
		if err != nil {
			return shareConfig{}, fmt.Errorf("invalid server from environment/config: %w", err)
		}

		cfg.server = pair
	}

	return cfg, nil
}

// runShare creates a QUIC connection to the relay server, and creates a unique
// token to address the QUIC connection. Terminating this connection will terminate
// the share. Additionally, post quantum encryption is enabled on top of classical
// encryption for they key exchange.
func runShare(args []string) error {
	_, err := parseShareFlags(args)
	if err != nil {
		return err
	}

	// TODO: unimplemented
	return nil
}
