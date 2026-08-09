// The ca subcommand manages the private certificate authority that share,
// get, and relay use to identify each other. We do mTLS with a self-signed
// root instead of the public web PKI, so every node needs a certificate
// issued by this same CA. These are ordinary TLS 1.3 certificates - QUIC
// requires TLS 1.3, so the cert model here is exactly what the QUIC
// handshake between nodes needs.

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"tornato.dev/ggrok/v2/internal/ca"
)

// caUsage marks the usage string for the ca command space.
const caUsage = `ggrok ca - manage the private certificate authority

Usage:
  ggrok ca init   [flags]
  ggrok ca issue  [flags]
  ggrok ca list   [flags]
  ggrok ca revoke [flags]
`

// caCertFile and caKeyFile are the well-known names `ca init` writes the
// root CA's certificate and key under, and every other ca sub-verb reads
// them back from.
const (
	caCertFile = "cert.pem"
	caKeyFile  = "key.pem"
)

// caDirFlagHelp is the -ca-dir flag description shared by every sub-verb
// other than init, which writes the directory instead of reading it.
const caDirFlagHelp = "directory containing the root CA's key and certificate (default ~/.ggrok/ca)"

// tableTabWidth and tableColumnPadding are the column spacing `ca list`
// renders its table with.
const (
	tableTabWidth      = 4
	tableColumnPadding = 2
)

// caCommands maps a ca sub-verb to the function that handles it.
var caCommands = map[string]func(args []string) error{
	"init":   runCAInit,
	"issue":  runCAIssue,
	"list":   runCAList,
	"revoke": runCARevoke,
}

// runCA dispatches to the proper ca sub-verb. Unlike the top-level share
// default, there is no sensible default sub-verb, so a bare `ggrok ca`
// prints usage instead of silently doing nothing.
func runCA(args []string) error {
	return dispatch(caCommands, args, runCAUsage)
}

// runCAUsage prints the ca command space's usage and reports it as a usage
// error, since a bare `ggrok ca` with no sub-verb isn't a valid invocation.
func runCAUsage(_ []string) error {
	fmt.Fprint(os.Stderr, caUsage)
	return errUsage
}

// defaultCADir returns ~/.ggrok/ca, the well-known location `ca init` uses
// and every other ca sub-verb falls back to when -ca-dir is omitted.
func defaultCADir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}

	return filepath.Join(home, ".ggrok", "ca"), nil
}

// resolveCADir sets *dir to defaultCADir if it's empty. Every ca sub-verb's
// -ca-dir (and init's -out) falls back the same way.
func resolveCADir(dir *string) error {
	if *dir != "" {
		return nil
	}

	def, err := defaultCADir()
	if err != nil {
		return err
	}

	*dir = def
	return nil
}

// loadCA reads the root CA's certificate and key out of caDir so a sub-verb
// can sign with it.
func loadCA(caDir string) (*ca.CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(caDir, caCertFile))
	if err != nil {
		return nil, fmt.Errorf("read root certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(caDir, caKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}

	root, err := ca.Load(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load CA from %s: %w", caDir, err)
	}

	return root, nil
}

// caInitConfig is the parsed and validated input to `ca init`.
type caInitConfig struct {
	// out is the directory the root CA's key and certificate are written to.
	out string

	// commonName is the identity embedded in the root CA's certificate.
	commonName string

	// validity is how long the root CA remains valid for.
	validity time.Duration
}

// runCAInit generates a new root CA keypair and self-signed certificate.
func runCAInit(args []string) error {
	fs := flag.NewFlagSet("ca init", flag.ExitOnError)
	fs.SetOutput(os.Stderr)

	var cfg caInitConfig
	fs.StringVar(&cfg.out, "out", "", "directory to write the root CA's key and certificate to (default ~/.ggrok/ca)")
	fs.StringVar(&cfg.commonName, "common-name", "ggrok root CA", "identity embedded in the root CA's certificate")
	fs.DurationVar(&cfg.validity, "validity", ca.DefaultCAValidity, "how long the root certificate is valid")

	if err := parseFlags(fs, args); err != nil {
		return err
	}

	if err := resolveCADir(&cfg.out); err != nil {
		return err
	}

	// A second `ca init` over an existing root would silently orphan every
	// certificate it already signed, since their trust chain depends on
	// this exact key. Refuse rather than clobber.
	if _, err := os.Stat(filepath.Join(cfg.out, caCertFile)); err == nil {
		return fmt.Errorf("a CA already exists at %s; remove it first if you mean to replace it", cfg.out)
	}

	bundle, err := ca.Init(cfg.commonName, cfg.validity)
	if err != nil {
		return fmt.Errorf("generate root CA: %w", err)
	}

	if err := os.MkdirAll(cfg.out, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", cfg.out, err)
	}

	if err := os.WriteFile(filepath.Join(cfg.out, caCertFile), bundle.CertPEM, 0o600); err != nil {
		return fmt.Errorf("write root certificate: %w", err)
	}

	if err := os.WriteFile(filepath.Join(cfg.out, caKeyFile), bundle.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write root key: %w", err)
	}

	fmt.Fprintf(os.Stdout, "initialized root CA %q in %s, valid until %s\n",
		cfg.commonName, cfg.out, bundle.Cert.NotAfter.Format(time.RFC3339))

	return nil
}

// caIssueConfig is the parsed and validated input to `ca issue`.
type caIssueConfig struct {
	// caDir is the directory containing the root CA's key and certificate.
	caDir string

	// commonName is the identity being issued a certificate - a particular
	// share/get client, or a relay.
	commonName string

	// out is the output path for the newly issued certificate and key.
	out string

	// ttl is how long the issued certificate is valid for.
	ttl time.Duration

	// server marks the certificate for server authentication as well as
	// client authentication - required for relay's own identity, since
	// share/listen verify relay's certificate as a TLS server cert when
	// they dial it.
	server bool

	// dnsNames and ips are the Subject Alternative Names embedded in the
	// certificate. Required for -server certificates: a TLS client
	// verifies the server's certificate against the address it dialed,
	// so relay's cert needs a SAN matching however share/listen will
	// reach it (e.g. -ip 127.0.0.1, or -dns-name relay.example.com).
	dnsNames []string
	ips      []net.IP
}

// runCAIssue issues a leaf certificate, signed by the root CA, for a given
// client or relay identity.
func runCAIssue(args []string) error {
	fs := flag.NewFlagSet("ca issue", flag.ExitOnError)
	fs.SetOutput(os.Stderr)

	var cfg caIssueConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "", caDirFlagHelp)
	fs.StringVar(&cfg.commonName, "common-name", "", "identity to issue a certificate for")
	fs.StringVar(&cfg.out, "out", "", "directory to write the issued certificate, key, and CA certificate to")
	fs.DurationVar(&cfg.ttl, "ttl", ca.DefaultDeviceValidity, "how long the issued certificate is valid for")
	fs.BoolVar(
		&cfg.server,
		"server",
		false,
		"also mark the certificate for server authentication (required for relay's identity)",
	)
	fs.Func(
		"dns-name",
		"a DNS name SAN to embed (repeatable; required for -server certs reached by hostname)",
		func(name string) error {
			cfg.dnsNames = append(cfg.dnsNames, name)
			return nil
		},
	)
	fs.Func(
		"ip",
		"an IP SAN to embed (repeatable; required for -server certs reached by IP, e.g. 127.0.0.1)",
		func(s string) error {
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("invalid IP %q", s)
			}

			cfg.ips = append(cfg.ips, ip)
			return nil
		},
	)

	if err := parseFlags(fs, args); err != nil {
		return err
	}

	if cfg.commonName == "" {
		fs.Usage()
		return fmt.Errorf("-common-name is required")
	}

	if cfg.out == "" {
		fs.Usage()
		return fmt.Errorf("-out is required")
	}

	if err := resolveCADir(&cfg.caDir); err != nil {
		return err
	}

	root, err := loadCA(cfg.caDir)
	if err != nil {
		return err
	}

	bundle, err := root.Issue(ca.IssueRequest{
		CommonName: cfg.commonName,
		Validity:   cfg.ttl,
		Server:     cfg.server,
		DNSNames:   cfg.dnsNames,
		IPs:        cfg.ips,
	})
	if err != nil {
		return fmt.Errorf("issue certificate: %w", err)
	}

	if err := ca.Store(cfg.caDir, bundle.Cert, bundle.CertPEM); err != nil {
		return fmt.Errorf("record issued certificate: %w", err)
	}

	if err := os.MkdirAll(cfg.out, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", cfg.out, err)
	}

	// cert.pem/key.pem/ca.pem mirrors the layout share/get expect in their
	// own config directory, so -out can point straight at one.
	if err := os.WriteFile(filepath.Join(cfg.out, "cert.pem"), bundle.CertPEM, 0o600); err != nil {
		return fmt.Errorf("write issued certificate: %w", err)
	}

	if err := os.WriteFile(filepath.Join(cfg.out, "key.pem"), bundle.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write issued key: %w", err)
	}

	if err := os.WriteFile(filepath.Join(cfg.out, "ca.pem"), root.CertPEM, 0o600); err != nil {
		return fmt.Errorf("write root certificate: %w", err)
	}

	fmt.Fprintf(os.Stdout, "issued certificate for %q (serial %s) in %s, valid until %s\n",
		cfg.commonName, bundle.Cert.SerialNumber.Text(ca.SerialTextBase), cfg.out,
		bundle.Cert.NotAfter.Format(time.RFC3339))

	return nil
}

// caListConfig is the parsed and validated input to `ca list`.
type caListConfig struct {
	// caDir is the directory containing the root CA's key and certificate.
	caDir string
}

// runCAList lists certificates issued by the root CA.
func runCAList(args []string) error {
	fs := flag.NewFlagSet("ca list", flag.ExitOnError)
	fs.SetOutput(os.Stderr)

	var cfg caListConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "", caDirFlagHelp)

	if err := parseFlags(fs, args); err != nil {
		return err
	}

	if err := resolveCADir(&cfg.caDir); err != nil {
		return err
	}

	certs, err := ca.List(cfg.caDir)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	if len(certs) == 0 {
		fmt.Fprintln(os.Stdout, "no certificates issued")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, tableTabWidth, tableColumnPadding, ' ', 0)
	fmt.Fprintln(w, "COMMON NAME\tSERIAL\tSTATUS\tEXPIRES")
	for _, c := range certs {
		status := "issued"
		switch {
		case c.Revoked:
			status = "revoked"
		case time.Now().After(c.Cert.NotAfter):
			status = "expired"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			c.Cert.Subject.CommonName, c.Cert.SerialNumber.Text(ca.SerialTextBase), status,
			c.Cert.NotAfter.Format(time.RFC3339))
	}

	return w.Flush()
}

// caRevokeConfig is the parsed and validated input to `ca revoke`.
type caRevokeConfig struct {
	// caDir is the directory containing the root CA's key and certificate.
	caDir string

	// commonName is the identity whose certificate should be revoked.
	commonName string
}

// runCARevoke revokes a previously issued certificate.
func runCARevoke(args []string) error {
	fs := flag.NewFlagSet("ca revoke", flag.ExitOnError)
	fs.SetOutput(os.Stderr)

	var cfg caRevokeConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "", caDirFlagHelp)
	fs.StringVar(&cfg.commonName, "common-name", "", "identity whose certificate should be revoked")

	if err := parseFlags(fs, args); err != nil {
		return err
	}

	if cfg.commonName == "" {
		fs.Usage()
		return fmt.Errorf("-common-name is required")
	}

	if err := resolveCADir(&cfg.caDir); err != nil {
		return err
	}

	if err := ca.Revoke(cfg.caDir, cfg.commonName); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}

	fmt.Fprintf(os.Stdout, "revoked certificate(s) for %q\n", cfg.commonName)

	return nil
}
