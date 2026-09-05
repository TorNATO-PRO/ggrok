// The relay subcommand runs the rendezvous server that brokers between a
// share (publisher) and any number of listen (subscriber) peers holding the
// matching token. It pairs their connections by session and splices the
// forwarded ones together; it never terminates the tunnelled service itself.
//
// It authenticates to its peers with a certificate issued by our CA (see the
// ca subcommand), and they authenticate to it the same way - all mTLS, no
// public web PKI involved. What it splices is end-to-end encrypted under keys
// derived from the session's token, which relay never sees, so a relay
// operator can route traffic without being able to read it.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/relay"
)

// relayConfig is the parsed and validated input to a relay.
type relayConfig struct {
	// listen is the address relay binds its TCP listener to, carrying both
	// the control connections and the per-stream data connections.
	listen hostport.HostPort

	// certFile is the path to the relay's own certificate, proving to peers
	// that this process is in fact the relay it claims to be.
	certFile string

	// keyFile is the path to the private key paired with certFile.
	keyFile string

	// caFile is the path to the CA certificate used to verify a peer's
	// (share/get client's) certificate.
	caFile string

	// revokedFile is an optional path to a newline-delimited serial list
	// (ggrok ca crl) of certificates the CA has since revoked; a
	// connecting peer matching one is rejected even though its chain
	// still verifies against caFile.
	revokedFile string

	// admin enables relay's admin plane, which is off unless asked for. An
	// operator who does not want one then has no admin surface at all,
	// rather than one gated solely on nobody holding a certificate with
	// the admin role.
	admin bool
}

// relayUsage marks the usage string for the relay subcommand.
const relayUsage = `ggrok relay - run the rendezvous server that brokers shares and gets

Usage:
  ggrok relay [flags]

Flags:
`

// parseRelayFlags parses the flags for the relay command into a validated
// relayConfig struct.
func parseRelayFlags(args []string) (relayConfig, error) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, relayUsage)
		fs.PrintDefaults()
	}

	var cfg relayConfig
	fs.Func("listen", "the address to bind relay's listener to", func(hostPortPair string) error {
		pair, err := hostport.Parse(hostPortPair)
		if err != nil {
			return err
		}

		cfg.listen = pair
		return nil
	})

	fs.StringVar(&cfg.certFile, "cert-file", "", "path to the relay's own certificate")
	fs.StringVar(&cfg.keyFile, "key-file", "", "path to the relay's private key")
	fs.StringVar(&cfg.caFile, "ca-file", "", "path to the CA certificate used to verify peers")
	fs.StringVar(&cfg.revokedFile, "revoked-file", "",
		"path to a revoked-serial list from `ggrok ca crl` (optional; omit to skip revocation checks)")
	fs.BoolVar(&cfg.admin, "admin", false,
		"accept admin connections from clients holding a certificate issued with `ggrok ca issue -admin`")

	if err := parseFlags(fs, args); err != nil {
		return relayConfig{}, err
	}

	for _, path := range []*string{&cfg.certFile, &cfg.keyFile, &cfg.caFile, &cfg.revokedFile} {
		if err := expandHomeInto(path); err != nil {
			return relayConfig{}, err
		}
	}

	return cfg, nil
}

// runRelay runs the relay command, brokering connections between shares
// and listeners without ever terminating the tunnelled service itself.
func runRelay(args []string) error {
	cfg, err := parseRelayFlags(args)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return relay.Run(ctx, relay.Config{
		Listen:      cfg.listen,
		CertFile:    cfg.certFile,
		KeyFile:     cfg.keyFile,
		CAFile:      cfg.caFile,
		RevokedFile: cfg.revokedFile,
		Admin:       cfg.admin,
	})
}
