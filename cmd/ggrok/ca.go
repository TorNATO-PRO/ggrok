// The ca subcommand manages the private certificate authority that share,
// listen, and relay use to identify each other. We do mTLS with a self-signed
// root instead of the public web PKI, so every node needs a certificate
// issued by this same CA. These are ordinary TLS 1.3 certificates - every
// mTLS handshake between nodes is pinned to TLS 1.3.

package main

import (
	"crypto/x509"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"tornato.dev/ggrok/v2/internal/ca"
)

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

// tableTabWidth and tableColumnPadding are the column spacing every ggrok
// table - `ca list`, `admin ls` - is rendered with.
const (
	tableTabWidth      = 4
	tableColumnPadding = 2
)

// defaultCADir returns ~/.ggrok/ca, the well-known location `ca init` uses
// and every other ca sub-verb falls back to when -ca-dir is omitted.
func defaultCADir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}

	return filepath.Join(home, ".ggrok", "ca"), nil
}

// resolveCADir sets *dir to defaultCADir if it's empty, and expands a
// leading "~/" either way. Every ca sub-verb's -ca-dir (and init's -out)
// falls back and expands the same way.
func resolveCADir(dir *string) error {
	if *dir == "" {
		def, err := defaultCADir()
		if err != nil {
			return err
		}

		*dir = def
		return nil
	}

	return expandHomeInto(dir)
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

// newCAInitCommand generates a new root CA keypair and self-signed certificate.
func newCAInitCommand() *cobra.Command {
	cmd := newCommand("init", "Create a private certificate authority")
	fs := cmd.Flags()

	var cfg caInitConfig
	fs.StringVar(&cfg.out, "out", "", "directory to write the root CA's key and certificate to (default ~/.ggrok/ca)")
	fs.StringVar(&cfg.commonName, "common-name", "ggrok root CA", "identity embedded in the root CA's certificate")
	fs.DurationVar(&cfg.validity, "validity", ca.DefaultCAValidity, "how long the root certificate is valid")

	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if err := resolveCADir(&cfg.out); err != nil {
			return err
		}

		bundle, err := ca.Init(cfg.commonName, cfg.validity)
		if err != nil {
			return fmt.Errorf("generate root CA: %w", err)
		}

		if err := writeCredentials(cfg.out, map[string][]byte{
			caCertFile: bundle.CertPEM,
			caKeyFile:  bundle.KeyPEM,
		}); err != nil {
			return err
		}

		p := stdoutColors()
		fmt.Fprintf(os.Stdout, "%s root CA %q in %s, valid until %s\n",
			p.green("initialized"), cfg.commonName, cfg.out, bundle.Cert.NotAfter.Format(time.RFC3339))

		return nil
	}
	return cmd
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

	// admin authorizes the certificate on relay's admin plane. It is the
	// only certificate distinction that is an authorization decision, which
	// is why it rides on an extended key usage rather than on the CN.
	admin bool
}

// newCAIssueCommand issues a leaf certificate, signed by the root CA, for a given
// client or relay identity.
func newCAIssueCommand() *cobra.Command {
	cmd := newCommand("issue", "Issue a peer certificate")
	fs := cmd.Flags()

	var cfg caIssueConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "", caDirFlagHelp)
	fs.StringVar(&cfg.commonName, "common-name", "", "identity to issue a certificate for")
	fs.StringVar(&cfg.out, "out", "", "directory to write the issued certificate, key, and CA certificate to")
	fs.DurationVar(&cfg.ttl, "ttl", ca.DefaultDeviceValidity, "how long the issued certificate is valid for")
	fs.BoolVar(
		&cfg.server,
		"server",
		false,
		"mark the certificate for server authentication instead of client (required for relay's identity)",
	)
	fs.BoolVar(
		&cfg.admin,
		"admin",
		false,
		"authorize the certificate on relay's admin plane (see `ggrok admin`; relay must run with -admin)",
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

	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if cfg.commonName == "" {
			return fmt.Errorf("-common-name is required")
		}

		if cfg.out == "" {
			return fmt.Errorf("-out is required")
		}

		if err := expandHomeInto(&cfg.out); err != nil {
			return err
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
			Admin:      cfg.admin,
			DNSNames:   cfg.dnsNames,
			IPs:        cfg.ips,
		})
		if err != nil {
			return fmt.Errorf("issue certificate: %w", err)
		}

		if err := ca.Store(cfg.caDir, bundle.Cert, bundle.CertPEM); err != nil {
			return fmt.Errorf("record issued certificate: %w", err)
		}

		if err := writeCredentials(cfg.out, map[string][]byte{
			"cert.pem": bundle.CertPEM,
			"key.pem":  bundle.KeyPEM,
			"ca.pem":   root.CertPEM,
		}); err != nil {
			return err
		}

		p := stdoutColors()
		fmt.Fprintf(os.Stdout, "%s certificate for %q (serial %s) in %s, valid until %s\n",
			p.green("issued"), cfg.commonName, bundle.Cert.SerialNumber.Text(ca.SerialTextBase), cfg.out,
			bundle.Cert.NotAfter.Format(time.RFC3339))

		return nil
	}
	return cmd
}

// extKeyUsageNames maps the extended key usages `ca issue` puts on a leaf to
// the role names `ca list` shows.
//
//nolint:exhaustive // deliberately only the usages ca issue writes; certRole renders anything else by number
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth: "server",
	x509.ExtKeyUsageClientAuth: "node",
}

// certRole renders what a certificate is authorized to do, for `ca list`.
//
// It is worth a column because losing a role fails silently: a bundle
// reissued by an older binary, or with the flag forgotten, produces a
// perfectly valid certificate that is simply refused by the one path it was
// meant for - with nothing at issuance time to say so. This is where that
// becomes visible before someone needs it.
func certRole(cert *x509.Certificate) string {
	var roles []string
	// Only the two usages `ca issue` puts on a leaf are named. Anything else
	// came from outside this tool and is reported by number rather than
	// silently dropped, so an unexpected certificate looks unexpected.
	for _, usage := range cert.ExtKeyUsage {
		name, known := extKeyUsageNames[usage]
		if !known {
			name = fmt.Sprintf("eku(%d)", usage)
		}
		roles = append(roles, name)
	}
	if ca.HasAdminEKU(cert) {
		roles = append(roles, "admin")
	}
	if len(roles) == 0 {
		return "-"
	}

	return strings.Join(roles, "+")
}

// caListConfig is the parsed and validated input to `ca list`.
type caListConfig struct {
	// caDir is the directory containing the root CA's key and certificate.
	caDir string
}

// newCAListCommand lists certificates issued by the root CA.
func newCAListCommand() *cobra.Command {
	cmd := newCommand("list", "List issued certificates")
	fs := cmd.Flags()

	var cfg caListConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "", caDirFlagHelp)

	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if err := resolveCADir(&cfg.caDir); err != nil {
			return err
		}

		certs, err := ca.List(cfg.caDir)
		if err != nil {
			return fmt.Errorf("list certificates: %w", err)
		}

		p := stdoutColors()
		if len(certs) == 0 {
			fmt.Fprintln(os.Stdout, p.dim("no certificates issued"))
			return nil
		}

		t := newTable()
		t.rowf(p.bold, "COMMON NAME\tSERIAL\tROLE\tSTATUS\tEXPIRES\n")
		for _, c := range certs {
			// A certificate that can no longer be used is the reason to run this
			// command at all, so the row it is on carries the color rather than
			// the status word: whatever the reader's eye lands on first is the
			// line, and one word four columns in is easy to scan past.
			status := "issued"

			var style func(string) string
			switch {
			case c.Revoked:
				status, style = "revoked", p.red
			case time.Now().After(c.Cert.NotAfter):
				status, style = "expired", p.yellow
			}

			t.rowf(style, "%s\t%s\t%s\t%s\t%s\n",
				terminalText(c.Cert.Subject.CommonName), c.Cert.SerialNumber.Text(ca.SerialTextBase), certRole(c.Cert),
				status, c.Cert.NotAfter.Format(time.RFC3339))
		}

		return t.flush(os.Stdout)
	}
	return cmd
}

// caRevokeConfig is the parsed and validated input to `ca revoke`.
type caRevokeConfig struct {
	// caDir is the directory containing the root CA's key and certificate.
	caDir string

	// commonName is the identity whose certificate should be revoked.
	commonName string
}

// newCARevokeCommand revokes a previously issued certificate.
func newCARevokeCommand() *cobra.Command {
	cmd := newCommand("revoke", "Revoke certificates for an identity")
	fs := cmd.Flags()

	var cfg caRevokeConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "", caDirFlagHelp)
	fs.StringVar(&cfg.commonName, "common-name", "", "identity whose certificate should be revoked")

	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if cfg.commonName == "" {
			return fmt.Errorf("-common-name is required")
		}

		if err := resolveCADir(&cfg.caDir); err != nil {
			return err
		}

		if err := ca.Revoke(cfg.caDir, cfg.commonName); err != nil {
			return fmt.Errorf("revoke certificate: %w", err)
		}

		fmt.Fprintf(os.Stdout, "%s certificate(s) for %q\n", stdoutColors().green("revoked"), cfg.commonName)

		return nil
	}
	return cmd
}

// caCRLConfig is the parsed and validated input to `ca crl`.
type caCRLConfig struct {
	// caDir is the directory containing the root CA's key and certificate.
	caDir string

	// out is the path to write the revoked-serial list to.
	out string
}

// newCACRLCommand exports every revoked certificate's serial number to a plain
// newline-delimited file, meant to be copied out to the relay (see the
// relay -revoked-file flag) so ca revoke actually cuts a peer off instead
// of being pure local bookkeeping - relay never holds the CA's private key
// or directory, so this file is the only way it learns what's revoked.
func newCACRLCommand() *cobra.Command {
	cmd := newCommand("crl", "Export revoked certificate serials")
	fs := cmd.Flags()

	var cfg caCRLConfig
	fs.StringVar(&cfg.caDir, "ca-dir", "", caDirFlagHelp)
	fs.StringVar(&cfg.out, "out", "", "path to write the revoked-serial list to")

	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if cfg.out == "" {
			return fmt.Errorf("-out is required")
		}

		if err := expandHomeInto(&cfg.out); err != nil {
			return err
		}

		if err := resolveCADir(&cfg.caDir); err != nil {
			return err
		}

		serials, err := ca.RevokedSerials(cfg.caDir)
		if err != nil {
			return fmt.Errorf("read revoked certificates: %w", err)
		}

		if err := writeRevokedSerials(cfg.out, serials); err != nil {
			return fmt.Errorf("write %s: %w", cfg.out, err)
		}

		fmt.Fprintf(os.Stdout, "%s %d revoked serial(s) to %s\n",
			stdoutColors().green("wrote"), len(serials), cfg.out)

		return nil
	}
	return cmd
}

// writeRevokedSerials writes a complete CRL before replacing the destination.
// On Unix, the same-directory rename is atomic for concurrent reloads.
// The destination directory must be controlled by the operator.
func writeRevokedSerials(path string, serials map[string]struct{}) error {
	var b strings.Builder
	for _, serial := range slices.Sorted(maps.Keys(serials)) {
		b.WriteString(serial)
		b.WriteByte('\n')
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ggrok-crl-*")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(b.String()); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
