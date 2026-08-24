//go:build tls_e2e

package tlscert

import (
	"os"
	"testing"
)

// TestManualE2E_StagingCA performs a REAL ACME DNS-01 exchange against
// Let's Encrypt's staging CA and the real Cloudflare zone for
// docs/environment.md's domain. It requires CLOUDFLARE_DNS_API_TOKEN to
// be set (docs/security.md §7 — never committed) and real network/DNS
// access, so it is excluded from the default `go test ./...` /
// `make check` -- the same build-tag isolation the `hardware` tests use,
// applied here to an external-network dependency rather than physical
// hardware. Run manually via:
//
//	CGO_ENABLED=1 go test -tags tls_e2e ./internal/tlscert/... -run TestManualE2E_StagingCA -v
//
// after sourcing the real .env. See docs/runbook.md for when to
// re-run this (verifying ADR-8's DNS-01 flow against a new domain, or
// after rotating the Cloudflare token).
func TestManualE2E_StagingCA(t *testing.T) {
	if os.Getenv("CLOUDFLARE_DNS_API_TOKEN") == "" {
		t.Fatal("CLOUDFLARE_DNS_API_TOKEN is not set — this test must fail, not skip, per the same policy as internal/decode's fixture tests (docs/protocol-spec.md §5)")
	}

	dir := t.TempDir()
	mgr, err := NewManager(Config{
		Domains:         []string{tlsTestDomain(t)},
		DNSProviderName: "cloudflare",
		CacheDir:        dir,
		UseStagingCA:    true,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	cert, err := mgr.TLSConfig().GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("obtained certificate has an empty chain")
	}
	t.Logf("obtained a staging certificate with %d chain element(s)", len(cert.Certificate))
}
