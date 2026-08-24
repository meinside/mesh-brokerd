//go:build tls_e2e

package tlscert

import (
	"os"
	"testing"
)

// TestManualE2E_CachedReuse verifies that a second Manager built
// against the same CacheDir reuses the cached certificate/account
// rather than performing a second real ACME DNS-01 exchange — the
// property ADR-8 relies on to avoid hitting Let's Encrypt's rate
// limits on every brokerd restart. Same manual-only rationale as
// TestManualE2E_StagingCA (smoke_manual_test.go); run via:
//
//	CGO_ENABLED=1 go test -tags tls_e2e -count=1 ./internal/tlscert/... -run TestManualE2E_CachedReuse -v
func TestManualE2E_CachedReuse(t *testing.T) {
	if os.Getenv("CLOUDFLARE_DNS_API_TOKEN") == "" {
		t.Fatal("CLOUDFLARE_DNS_API_TOKEN is not set — this test must fail, not skip")
	}

	dir := t.TempDir()
	cfg := Config{
		Domains:         []string{tlsTestDomain(t)},
		DNSProviderName: "cloudflare",
		CacheDir:        dir,
		UseStagingCA:    true,
	}

	if _, err := NewManager(cfg); err != nil {
		t.Fatalf("first NewManager (expected to obtain a fresh certificate): %v", err)
	}

	// A second Manager against the same dir must load the certificate
	// just cached above rather than performing another ACME exchange.
	// Verified manually (docs/runbook.md) by checking that only one
	// "acme: Obtaining bundled SAN certificate" log line appears across
	// both calls in this test's output.
	if _, err := NewManager(cfg); err != nil {
		t.Fatalf("second NewManager (expected to reuse the cache): %v", err)
	}
}
