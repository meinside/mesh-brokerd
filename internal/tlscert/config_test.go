package tlscert

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	base := Config{
		Domains:         []string{"broker.example.com"},
		DNSProviderName: "cloudflare",
		CacheDir:        "/tmp/does-not-need-to-exist",
	}

	if err := base.validate(); err != nil {
		t.Fatalf("validate on a complete config: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no domains", func(c *Config) { c.Domains = nil }},
		{"no DNS provider", func(c *Config) { c.DNSProviderName = "" }},
		{"no cache dir", func(c *Config) { c.CacheDir = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if err := cfg.validate(); err == nil {
				t.Errorf("validate() = nil, want an error when %s", tc.name)
			}
		})
	}
}

// TestConfig_CADirURL guards the switch that decides whether real,
// rate-limited, publicly-trusted certificates are requested. Getting it
// backwards would either burn production rate limits during testing or
// silently serve untrusted staging certs in production.
func TestConfig_CADirURL(t *testing.T) {
	prod := Config{}.caDirURL()
	staging := Config{UseStagingCA: true}.caDirURL()

	if prod == staging {
		t.Fatal("production and staging CA directory URLs are identical")
	}
	if !strings.Contains(staging, "staging") {
		t.Errorf("UseStagingCA=true gave %q, which does not look like a staging endpoint", staging)
	}
	if strings.Contains(prod, "staging") {
		t.Errorf("UseStagingCA=false gave %q, which looks like a staging endpoint", prod)
	}
}

// TestManager_GetCertificateBeforeIssuance confirms the TLS handshake
// path fails cleanly (rather than panicking or serving a zero-value
// certificate) if it is somehow reached before a certificate exists.
func TestManager_GetCertificateBeforeIssuance(t *testing.T) {
	m := &Manager{}
	if _, err := m.TLSConfig().GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Error("GetCertificate returned no error with no certificate loaded, want an error")
	}
}

func TestManager_NeedsRenewal(t *testing.T) {
	t.Run("no certificate yet", func(t *testing.T) {
		m := &Manager{}
		if !m.needsRenewal() {
			t.Error("needsRenewal = false with no certificate, want true")
		}
	})

	t.Run("fresh certificate", func(t *testing.T) {
		certPEM, keyPEM := generateTestCert(t, 60*24*time.Hour)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("X509KeyPair: %v", err)
		}
		m := &Manager{cert: &cert}
		if m.needsRenewal() {
			t.Error("needsRenewal = true for a certificate valid for 60 days, want false")
		}
	})

	t.Run("expiring certificate", func(t *testing.T) {
		certPEM, keyPEM := generateTestCert(t, time.Hour)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("X509KeyPair: %v", err)
		}
		m := &Manager{cert: &cert}
		if !m.needsRenewal() {
			t.Error("needsRenewal = false for a certificate expiring in 1 hour, want true")
		}
	})
}

// TestManager_TLSConfigServesCurrentCertificate confirms TLSConfig hands
// back whatever the Manager currently holds, so a renewal performed by
// RunRenewalLoop is picked up by new handshakes without rebuilding the
// *tls.Config that listeners were started with.
func TestManager_TLSConfigServesCurrentCertificate(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, 60*24*time.Hour)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	m := &Manager{}
	cfg := m.TLSConfig() // captured before any certificate exists

	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("expected an error before a certificate is set")
	}

	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()

	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate after setting a certificate: %v", err)
	}
	if got != &cert {
		t.Error("GetCertificate did not return the Manager's current certificate")
	}
}

func TestRunRenewalLoop_StopsOnContextCancel(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, 60*24*time.Hour)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	m := &Manager{cert: &cert}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// A short interval with a certificate that does not need renewal:
		// the loop should tick, decide there is nothing to do, and exit
		// promptly on cancellation without ever calling obtainOrRenew
		// (which would need network access).
		m.RunRenewalLoop(ctx, 10*time.Millisecond, func(error) {
			t.Error("onError called unexpectedly -- no renewal should have been attempted")
		})
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunRenewalLoop did not return within 2s of cancellation")
	}
}

// tlsTestDomain returns the domain the manual ACME tests should use.
//
// Taken from the environment rather than hardcoded: these tests perform a
// real DNS-01 exchange against a real zone, which is deployment data and
// does not belong in a published repository. The manual tests are already
// behind build tags and need a provider token anyway
// (docs/runbook.md §3).
func tlsTestDomain(t *testing.T) string {
	t.Helper()
	d := os.Getenv("BROKERD_TLS_TEST_DOMAIN")
	if d == "" {
		t.Fatal("BROKERD_TLS_TEST_DOMAIN is not set — set it to a hostname in a zone the DNS provider token controls")
	}
	return d
}
