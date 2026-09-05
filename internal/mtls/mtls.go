// Package mtls builds the mutual-TLS config shared by share, listen, and
// relay: every control and data connection uses it for TLS 1.3 over TCP. All
// three verify each other against a private CA instead of the public web PKI
// - every node needs a certificate issued by that same CA, and every node
// verifies its peer against it.
//
// This authenticates and protects each leg to relay separately. It is not
// what keeps relay out of the forwarded traffic: relay terminates TLS on both
// legs, so the tunnel is sealed independently on top of it (see
// proto.EncryptedConn).
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"maps"
	"os"
	"sync/atomic"

	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/proto"
)

// RevocationSet is the set of certificate serials relay currently refuses.
//
// It is a handle holding a pointer rather than a plain map because the set
// has to be replaceable while the listener is live: [LoadConfig] captures it
// once, at startup, and a captured map could never change - which is what
// made `ggrok ca revoke` pure bookkeeping until a relay restart. Swapping the
// pointer is what lets `ggrok admin reload-crl` take effect on the next
// handshake.
//
// The zero value is a usable empty set, so a relay started without a revoked
// file can still be given one later.
type RevocationSet struct {
	v atomic.Pointer[map[string]struct{}]
}

// NewRevocationSet returns a set holding serials. A nil or empty map is fine
// and means "refuse nobody, for now".
func NewRevocationSet(serials map[string]struct{}) *RevocationSet {
	s := &RevocationSet{}
	s.Replace(serials)

	return s
}

// Replace swaps in a new set of serials, atomically, for every subsequent
// handshake. Connections already established are unaffected - a TLS handshake
// happens once - which is why reloading a CRL is only half of enforcement and
// the other half is closing what the new list now covers.
func (s *RevocationSet) Replace(serials map[string]struct{}) {
	next := make(map[string]struct{}, len(serials))
	maps.Copy(next, serials)
	s.v.Store(&next)
}

// Contains reports whether serial is currently revoked.
func (s *RevocationSet) Contains(serial string) bool {
	current := s.v.Load()
	if current == nil {
		return false
	}
	_, revoked := (*current)[serial]

	return revoked
}

// Len is how many serials the set currently holds.
func (s *RevocationSet) Len() int {
	current := s.v.Load()
	if current == nil {
		return 0
	}

	return len(*current)
}

// LoadConfig reads certFile/keyFile as this node's own identity and caFile
// as the CA used to verify the peer, and builds a [tls.Config] requiring
// mutual authentication.
//
// server distinguishes relay's listener (which must additionally require
// and verify the connecting client's certificate) from a dialing share or
// listen client (which verifies relay's server certificate via the same CA
// pool instead of the public web PKI, so no InsecureSkipVerify is needed).
//
// revoked is relay's revocation list (see ca.ParseRevokedSerials and
// [RevocationSet]); nil means the check can never be enabled on this config,
// and it's only ever consulted when server is true - a chain-valid cert of
// relay's own is never revoked out from under a dialing share/listen client
// mid-flow the way a client's can be by its operator.
func LoadConfig(
	certFile, keyFile, caFile string,
	server bool,
	revoked *RevocationSet,
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

		// Installed whenever a set exists, even an empty one, rather than
		// only when it starts non-empty. Installing conditionally on the
		// startup contents would mean a relay started without a CRL could
		// never gain one: the hook it would need was never wired up, and
		// a config's callbacks cannot be changed once the listener is
		// live. The empty case is fast-pathed inside the callback instead.
		if revoked != nil {
			cfg.VerifyPeerCertificate = verifyNotRevoked(revoked)
		}

		// A resumed TLS 1.3 connection skips the client Certificate
		// message and doesn't re-run VerifyPeerCertificate, which is
		// the hook verifyNotRevoked above depends on - so leaving
		// session tickets enabled would let a revoked cert keep
		// authenticating via a cached ticket for the ticket's
		// lifetime, silently undermining -revoked-file.
		//
		// It is load-bearing for the admin role check too: that check
		// reads the peer's leaf certificate, which a resumed connection
		// would not have presented.
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
func verifyNotRevoked(revoked *RevocationSet) func([][]byte, [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		// The common case is an empty set, and this runs on every
		// handshake: check it once rather than per chain.
		if revoked.Len() == 0 {
			return nil
		}

		for _, chain := range verifiedChains {
			if len(chain) == 0 {
				continue
			}

			leaf := chain[0]
			if revoked.Contains(leaf.SerialNumber.Text(ca.SerialTextBase)) {
				return fmt.Errorf("certificate %q (serial %s) has been revoked",
					leaf.Subject.CommonName, leaf.SerialNumber.Text(ca.SerialTextBase))
			}
		}

		return nil
	}
}
