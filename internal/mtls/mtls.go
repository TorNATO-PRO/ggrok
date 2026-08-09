// Package mtls builds the mutual-TLS config shared by share, listen, and
// relay. All three speak QUIC to each other over a private CA instead of
// the public web PKI - every node needs a certificate issued by that same
// CA, and every node verifies its peer against it.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

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
func LoadConfig(certFile, keyFile, caFile string, server bool) (*tls.Config, error) {
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
	} else {
		cfg.RootCAs = pool
	}

	return cfg, nil
}
