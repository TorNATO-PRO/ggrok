// Package mtls builds the mutual-TLS config shared by share, listen, and
// relay: every TCP control/data connection uses it directly for TLS 1.3
// over TCP, and relay's QUIC listener (UDP-mode's data plane) reuses the
// exact same config, since QUIC's handshake is TLS 1.3 underneath. All
// three verify each other against a private CA instead of the public web
// PKI - every node needs a certificate issued by that same CA, and every
// node verifies its peer against it.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/proto"
)

// LoadConfig reads certFile/keyFile as this node's own identity and caFile
// as the CA used to verify the peer, and builds a [tls.Config] requiring
// mutual authentication.
//
// server distinguishes relay's listener (which must additionally require
// and verify the connecting client's certificate) from a dialing share or
// listen client (which verifies relay's server certificate via the same CA
// pool instead of the public web PKI, so no InsecureSkipVerify is needed).
//
// revokedSerials is relay's revocation list (see ca.ParseRevokedSerials);
// nil or empty skips the check entirely, and it's only ever consulted when
// server is true - a chain-valid cert of relay's own is never revoked out
// from under a dialing share/listen client mid-flow the way a client's can
// be by its operator.
func LoadConfig(
	certFile, keyFile, caFile string,
	server bool,
	revokedSerials map[string]struct{},
) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate/key: %w", err)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{proto.ALPN},
		MinVersion:   tls.VersionTLS13,
		// X25519MLKEM768 is a hybrid group: classical X25519 ECDH combined
		// with the ML-KEM-768 post-quantum KEM in a single key exchange, so
		// a break of either half alone doesn't break the session key.
		// Every peer in this system is our own Go 1.26+ build against the
		// same private CA, so there's no interop reason to allow a
		// classical-only fallback - pinning this as the sole preference
		// means a downgrade can't happen silently.
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}

	if server {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool

		if len(revokedSerials) > 0 {
			cfg.VerifyPeerCertificate = verifyNotRevoked(revokedSerials)
		}

		// A resumed TLS 1.3 connection skips the client Certificate
		// message and doesn't re-run VerifyPeerCertificate, which is
		// the hook verifyNotRevoked above depends on - so leaving
		// session tickets enabled would let a revoked cert keep
		// authenticating via a cached ticket for the ticket's
		// lifetime, silently undermining -revoked-file.
		cfg.SessionTicketsDisabled = true
	} else {
		cfg.RootCAs = pool
	}

	return cfg, nil
}

// verifyNotRevoked returns a VerifyPeerCertificate callback rejecting a
// peer whose certificate serial appears in revoked. By the time
// VerifyPeerCertificate runs, [tls.RequireAndVerifyClientCert] has already
// confirmed the chain is valid and unexpired - revocation is the one thing
// standard chain verification can't express, since a revoked cert would
// otherwise keep authenticating until it naturally expires (see
// ca.DefaultDeviceValidity).
func verifyNotRevoked(revoked map[string]struct{}) func([][]byte, [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, chain := range verifiedChains {
			if len(chain) == 0 {
				continue
			}

			leaf := chain[0]
			if _, isRevoked := revoked[leaf.SerialNumber.Text(ca.SerialTextBase)]; isRevoked {
				return fmt.Errorf("certificate %q (serial %s) has been revoked",
					leaf.Subject.CommonName, leaf.SerialNumber.Text(ca.SerialTextBase))
			}
		}

		return nil
	}
}
