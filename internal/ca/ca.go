package ca

import (
	"bufio"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultCAValidity is how long a root certificate lasts. The root is
	// long-lived because rotating it means re-provisioning every device.
	DefaultCAValidity = 10 * 365 * 24 * time.Hour

	// DefaultDeviceValidity is how long an issued device certificate lasts.
	// Short-lived certs are the revocation strategy: a leaked cert self-expires
	// rather than needing CRL/OCSP infrastructure.
	DefaultDeviceValidity = 90 * 24 * time.Hour

	// pemTypeCertificate defines a constant for the PEM type.
	pemTypeCertificate = "CERTIFICATE"

	// pemTypeMLDSAKey defines a constant for ML-DSA keys (serialized as PKCS#8).
	pemTypeMLDSAKey = "PRIVATE KEY"

	// SerialTextBase is the base certificate serials are rendered in, both
	// for their PEM filename under the issued/revoked subdirectories and for
	// display. Exported so callers (e.g. the ca CLI) format serials the same
	// way this package does.
	SerialTextBase = 16

	// serialBits is the width of a freshly generated serial number.
	serialBits = 128

	// issuedDirName and revokedDirName are the subdirectories of a CA
	// directory that List, Revoke, and Store agree on.
	issuedDirName  = "issued"
	revokedDirName = "revoked"
)

// Bundle is a freshly generated certificate and its private key,
// both of which are PEM-encoded.
type Bundle struct {
	// Cert is the x509 certificate embedded in our bundle
	Cert *x509.Certificate

	// CertPEM is the binary cryptographic data related to a cert.
	CertPEM []byte

	// KeyPEM is the binary cryptographic data related to a private key.
	KeyPEM []byte
}

// CA is a loaded certificate authority capable of signing device certificates.
type CA struct {
	// Cert is the x509 certificate which we use to sign things.
	Cert *x509.Certificate

	// CertPEM is the binary encoded certificate
	CertPEM []byte

	// key is the private key - remember not to upload this
	// to a relay server. This should live on a node that is
	// acting as the host for the CA.
	key any // *mldsa.SigningKey65
}

// IssueRequest describes a certificate to be signed.
type IssueRequest struct {
	// CommonName is the CN of the certificate.
	CommonName string

	// Validity determines how long the certificate should remain valid.
	Validity time.Duration

	// Server marks the certificate for server authentication as well as client
	// authentication. The relay needs one of these to present on its own
	// listener; publishing devices do not.
	Server bool

	// DNSNames marks the different DNS names that are covered under this certificate.
	DNSNames []string

	// IPs marks the different IPs that are covered under this certificate.
	IPs []net.IP
}

// serialLimit is the largest possible number you can have
// for a serial number.
var serialLimit = new(big.Int).Lsh(big.NewInt(1), serialBits)

// Init generates a new self-signed root certificate authority.
func Init(commonName string, validity time.Duration) (*Bundle, error) {
	if commonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	if validity <= 0 {
		validity = DefaultCAValidity
	}

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	cert, err := defineCertificate(commonName, validity)
	if err != nil {
		return nil, err
	}

	derEncodedSignedCert, err := signCertificate(cert, key)
	if err != nil {
		return nil, err
	}

	bundle, err := buildBundle(derEncodedSignedCert, key)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

// Load reads a certificate authority from PEM-encoded cert and key bytes.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("certificate %q is not a CA certificate", cert.Subject.CommonName)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in CA key")
	}

	key, err := parsePrivateKey(block)
	if err != nil {
		return nil, err
	}

	// Verify that the key matches the certificate's public key
	keyPublicKey := key.(*mldsa.PrivateKey).PublicKey() //nolint:errcheck // PublicKey() does not return an error
	if !keyPublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("CA Key does not match CA certificate")
	}

	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// Issue generates a keypair and signs a certificate for it.
func (c *CA) Issue(request IssueRequest) (*Bundle, error) {
	if request.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	if request.Validity <= 0 {
		request.Validity = DefaultDeviceValidity
	}

	now := time.Now()
	if notAfter := now.Add(request.Validity); notAfter.After(c.Cert.NotAfter) {
		return nil, fmt.Errorf(
			"requested validity outlives the CA certificate (CA expires %s)",
			c.Cert.NotAfter.Format(time.RFC3339),
		)
	}

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	// Every device cert can authenticate as a client; that is the publish gate.
	// Any valid cert is equally trusted to publish, so the CN is a label for
	// logging and audit, never an input to an authorization decision.
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if request.Server {
		usages = append(usages, x509.ExtKeyUsageServerAuth)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: request.CommonName},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(request.Validity),
		// Digital signature only: keyEncipherment is not valid for ML-DSA.
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usages,
		DNSNames:    request.DNSNames,
		IPAddresses: request.IPs,

		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derEncodedSignedCert, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, key.PublicKey(), c.key)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	return buildBundle(derEncodedSignedCert, key)
}

// ListedCertificate pairs a parsed certificate with whether it lives in the
// issued or revoked subdirectory.
type ListedCertificate struct {
	// Cert is the parsed certificate.
	Cert *x509.Certificate

	// Revoked is true if the certificate was found under the revoked
	// subdirectory rather than issued.
	Revoked bool

	// filePath is the path to the listed certificate's PEM file, used by
	// Revoke to relocate it without re-deriving a filename.
	filePath string
}

// List lists the certificates found in the passed directory. This application
// persists certificates in PEM files, and maintains two separate subdirectories
// within the parent caDirectory that are named issued and revoked specifically.
// The semantics are essentially what you would expect, with revoked containing revoked
// certificates, and issued containing (potentially) active certificates.
func List(caDirectory string) ([]ListedCertificate, error) {
	issued, err := readCertDir(filepath.Join(caDirectory, issuedDirName))
	if err != nil {
		return nil, fmt.Errorf("read issued certificates: %w", err)
	}

	revoked, err := readCertDir(filepath.Join(caDirectory, revokedDirName))
	if err != nil {
		return nil, fmt.Errorf("read revoked certificates: %w", err)
	}
	for i := range revoked {
		revoked[i].Revoked = true
	}

	return append(issued, revoked...), nil
}

// Revoke moves every issued, not-yet-revoked certificate whose CommonName
// matches commonName from caDirectory's issued subdirectory into its revoked
// subdirectory. Matching is by CommonName rather than serial because that's
// what an operator has on hand when responding to a compromised device, and
// it means a device that was re-issued under the same name gets fully cut
// off in one call rather than leaving an old cert live.
func Revoke(caDirectory, commonName string) error {
	if commonName == "" {
		return fmt.Errorf("common name is required")
	}

	issued, err := readCertDir(filepath.Join(caDirectory, issuedDirName))
	if err != nil {
		return fmt.Errorf("read issued certificates: %w", err)
	}

	revokedDir := filepath.Join(caDirectory, revokedDirName)

	var matched int
	for _, listed := range issued {
		if listed.Cert.Subject.CommonName != commonName {
			continue
		}

		if matched == 0 {
			if err := os.MkdirAll(revokedDir, 0o700); err != nil {
				return fmt.Errorf("create revoked directory: %w", err)
			}
		}

		dest := filepath.Join(revokedDir, filepath.Base(listed.filePath))
		if err := os.Rename(listed.filePath, dest); err != nil {
			return fmt.Errorf("revoke %s: %w", listed.filePath, err)
		}

		matched++
	}

	if matched == 0 {
		return fmt.Errorf("no issued certificate found for common name %q", commonName)
	}

	return nil
}

// RevokedSerials returns the serial number (SerialTextBase-encoded) of
// every certificate under caDirectory's revoked subdirectory. It's the
// write side of the relay's revocation check: relay never holds the CA's
// private key or directory, so it can't consult List/Revoke directly - an
// operator instead exports this set (see the ca crl subcommand) and copies
// it to the relay out of band.
func RevokedSerials(caDirectory string) (map[string]struct{}, error) {
	revoked, err := readCertDir(filepath.Join(caDirectory, revokedDirName))
	if err != nil {
		return nil, fmt.Errorf("read revoked certificates: %w", err)
	}

	serials := make(map[string]struct{}, len(revoked))
	for _, c := range revoked {
		serials[c.Cert.SerialNumber.Text(SerialTextBase)] = struct{}{}
	}

	return serials, nil
}

// ParseRevokedSerials reads the newline-delimited serial list RevokedSerials
// produces, so a relay can load it without ever needing the CA's directory
// or private key. Blank lines are ignored so the file can be hand-edited.
func ParseRevokedSerials(r io.Reader) (map[string]struct{}, error) {
	serials := make(map[string]struct{})

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		serials[line] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan revoked serials: %w", err)
	}

	return serials, nil
}

// Store persists a freshly issued certificate's public half under
// caDirectory's issued subdirectory, keyed by serial number, so List and
// Revoke can find it later. The private key is the caller's responsibility
// - it belongs wherever the operator asked for the issued credential to
// go, never inside the CA's own bookkeeping directory.
func Store(caDirectory string, cert *x509.Certificate, certPEM []byte) error {
	issuedDir := filepath.Join(caDirectory, issuedDirName)
	if err := os.MkdirAll(issuedDir, 0o700); err != nil {
		return fmt.Errorf("create issued directory: %w", err)
	}

	path := filepath.Join(issuedDir, cert.SerialNumber.Text(SerialTextBase)+".pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

// readCertDir parses every PEM file directly inside dir. A missing directory
// is treated as empty rather than an error, since a freshly initialized CA
// won't have issued (or revoked) anything yet.
func readCertDir(dir string) ([]ListedCertificate, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	certs := make([]ListedCertificate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		cert, err := ParseCertificate(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		certs = append(certs, ListedCertificate{Cert: cert, filePath: path})
	}

	return certs, nil
}

// ParseCertificate decodes the first certificate in a PEM block.
func ParseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("expected a %s block, got %q", pemTypeCertificate, block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// defineCertificate encapsulates the definition of a CA cert.
func defineCertificate(commonName string, validity time.Duration) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	certTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		// tolerate a tiny bit of clock skew
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	return certTemplate, nil
}

// signCertificate is responsible for signing a certificate.
func signCertificate(certTemplate *x509.Certificate, key *mldsa.PrivateKey) ([]byte, error) {
	derEncodedCertificate, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.PublicKey(), key)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca certificate: %w", err)
	}

	return derEncodedCertificate, nil
}

// buildBundle creates the bundle from the signed
// certificate and the private key.
func buildBundle(derEncodedCertificate []byte, key *mldsa.PrivateKey) (*Bundle, error) {
	// recreate the certificate from the derEncodedCertificate
	cert, err := x509.ParseCertificate(derEncodedCertificate)
	if err != nil {
		return nil, fmt.Errorf("parse generated certificate: %w", err)
	}

	// convert the ML-DSA key into PKCS#8 DER format
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	return &Bundle{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: derEncodedCertificate}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: pemTypeMLDSAKey, Bytes: keyDER}),
	}, nil
}

// parsePrivateKey takes a PEM block and returns the ML-DSA private key.
func parsePrivateKey(block *pem.Block) (any, error) {
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("expected PKCS#8 private key, got %q", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
	}

	mldsaKey, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected an ML-DSA key, got %T", key)
	}

	return mldsaKey, nil
}

// newSerial draws a random 128-bit serial. Random rather than sequential so
// the CA holds no issuance counter state between invocations.
func newSerial() (*big.Int, error) {
	upperBound := new(big.Int).Sub(serialLimit, big.NewInt(1))

	n, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	return n.Add(n, big.NewInt(1)), nil
}
