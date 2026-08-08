// The relay subcommand runs the QUIC-based rendezvous server that brokers
// between a share and a get. It maps a token to a client's session and can
// ask that client "send the file for token X", but it never reads or stores
// the file itself. It authenticates to its peers with a certificate issued
// by our CA (see the ca subcommand), and they authenticate to it the same
// way - all mTLS, no public web PKI involved.

package main

import (
	"flag"
	"fmt"
	"os"

	hostport "tornato.dev/ggrok/v2/internal"
)

// relayConfig is the parsed and validated input to a relay.
type relayConfig struct {
	// listen is the address the QUIC listener binds - this is a UDP address
	// at the packet level, since that's how QUIC's wire protocol works, but
	// it has nothing to do with a share's -udp forwarding mode, which is an
	// application-level concept layered on top of a QUIC connection.
	listen hostport.HostPort

	// certFile is the path to the relay's own certificate, proving to peers
	// that this process is in fact the relay it claims to be.
	certFile string

	// keyFile is the path to the private key paired with certFile.
	keyFile string

	// caFile is the path to the CA certificate used to verify a peer's
	// (share/get client's) certificate.
	caFile string
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
	fs.Func("listen", "the address to bind the QUIC listener to", func(hostPortPair string) error {
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

	if err := parseFlags(fs, args); err != nil {
		return relayConfig{}, err
	}

	return cfg, nil
}

// runRelay runs the relay command, brokering QUIC connections between
// shares and gets without ever reading the shared file itself.
func runRelay(args []string) error {
	_, err := parseRelayFlags(args)
	if err != nil {
		return err
	}

	// TODO: unimplemented
	return nil
}
