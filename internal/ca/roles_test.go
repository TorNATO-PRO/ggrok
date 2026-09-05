package ca_test

import (
	"crypto/x509"
	"slices"
	"testing"

	"tornato.dev/ggrok/v2/internal/ca"
)

// testRoot returns a loaded root CA to issue leaves from.
func testRoot(t *testing.T) *ca.CA {
	t.Helper()

	bundle, err := ca.Init("roles test root", ca.DefaultCAValidity)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ca.Load(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	return root
}

// TestIssuedRoles pins what each issue flag puts in a certificate.
//
// This exists because losing a role fails silently rather than loudly: a
// bundle reissued by an older binary, or with a flag forgotten, is a
// perfectly valid certificate that is simply refused by the one path it was
// meant for - with nothing at issuance time to say so. Nothing else in the
// system would notice.
func TestIssuedRoles(t *testing.T) {
	t.Parallel()

	root := testRoot(t)

	tests := []struct {
		name      string
		request   ca.IssueRequest
		wantUsage []x509.ExtKeyUsage
		wantAdmin bool
	}{
		{
			name:      "plain node",
			request:   ca.IssueRequest{CommonName: "node"},
			wantUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			// Dedicated-use: relay only ever listens, so its leaf must
			// not also claim a capability nothing in this system uses.
			name:      "relay is serverAuth only",
			request:   ca.IssueRequest{CommonName: "relay", Server: true},
			wantUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			// clientAuth is not optional on an admin cert: Go verifies
			// client chains against it, so one without it would fail the
			// handshake outright and never reach the role check.
			name:      "admin keeps clientAuth",
			request:   ca.IssueRequest{CommonName: "ops", Admin: true},
			wantUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			wantAdmin: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.request.Validity = ca.DefaultDeviceValidity
			bundle, err := root.Issue(tt.request)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}

			if !slices.Equal(bundle.Cert.ExtKeyUsage, tt.wantUsage) {
				t.Fatalf("ExtKeyUsage = %v, want %v", bundle.Cert.ExtKeyUsage, tt.wantUsage)
			}
			if got := ca.HasAdminEKU(bundle.Cert); got != tt.wantAdmin {
				t.Fatalf("HasAdminEKU = %v, want %v", got, tt.wantAdmin)
			}
		})
	}
}

// TestAdminEKUSurvivesEncoding checks the role through a full DER round trip,
// not just the template. UnknownExtKeyUsage is populated by the parser rather
// than carried over from the template, so asserting on an unparsed
// certificate would prove nothing about what a relay actually reads.
func TestAdminEKUSurvivesEncoding(t *testing.T) {
	t.Parallel()

	root := testRoot(t)
	bundle, err := root.Issue(ca.IssueRequest{
		CommonName: "ops", Validity: ca.DefaultDeviceValidity, Admin: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	reparsed, err := x509.ParseCertificate(bundle.Cert.Raw)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if !ca.HasAdminEKU(reparsed) {
		t.Fatal("the admin role did not survive encoding and reparsing")
	}
}

// TestHasAdminEKURejectsNil covers the guard: a snapshot or a role check
// reaching a connection without a leaf must answer "no", not panic.
func TestHasAdminEKURejectsNil(t *testing.T) {
	t.Parallel()

	if ca.HasAdminEKU(nil) {
		t.Fatal("a nil certificate was treated as an admin")
	}
	if ca.HasAdminEKU(&x509.Certificate{}) {
		t.Fatal("a certificate with no usages was treated as an admin")
	}
}
