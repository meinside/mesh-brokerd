// Package tlscert implements brokerd's automatic TLS certificate
// management (ADR-8 in docs/adr.md): obtaining and renewing a Let's
// Encrypt certificate via the ACME DNS-01 challenge, using
// go-acme/lego's provider registry so any of its ~200 supported DNS
// providers can be selected by name, with no brokerd code changes.
//
// ADR-8 originally specified golang.org/x/crypto/acme/autocert, but
// autocert only implements the "http-01" and "tls-alpn-01" challenge
// types — it has no DNS-01 support at all. This package replaces that
// approach; the underlying goals (no port 80, in-process automatic
// issuance/renewal, no external cron) are unchanged.
package tlscert

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// renewBefore is how far ahead of a certificate's expiry Manager
// renews it. 30 days matches Let's Encrypt's own recommended renewal
// window (90-day certificates, renew with a third of the lifetime
// left).
const renewBefore = 30 * 24 * time.Hour

// Config configures a Manager.
type Config struct {
	// Domains is the certificate's domain list. The first entry becomes
	// the certificate's CommonName; the rest are Subject Alternative
	// Names (docs/brokerd-config.md's listener.tls_cert_domains).
	Domains []string

	// Email is the ACME account's contact address. Optional — Let's
	// Encrypt does not require one, but it's used for expiry
	// notifications if the account's own renewal ever silently stops
	// working.
	Email string

	// DNSProviderName selects a go-acme/lego DNS provider by name
	// (docs/brokerd-config.md's listener.tls_dns_provider, e.g.
	// "cloudflare"). The provider reads its own credentials from
	// well-known environment variables (documented per-provider at
	// go-acme.github.io/lego/dns/) — never from brokerd's config.json.
	DNSProviderName string

	// CacheDir is where the ACME account key/registration and the
	// obtained certificate/key are persisted across restarts, so
	// brokerd never re-issues a certificate on every restart (avoiding
	// Let's Encrypt's rate limits).
	CacheDir string

	// UseStagingCA switches to Let's Encrypt's staging directory, which
	// has much looser rate limits and issues certificates not trusted
	// by real clients — for verifying the DNS-01 flow end-to-end before
	// pointing at the production CA.
	UseStagingCA bool
}

func (c Config) validate() error {
	if len(c.Domains) == 0 {
		return fmt.Errorf("tlscert: at least one domain is required")
	}
	if c.DNSProviderName == "" {
		return fmt.Errorf("tlscert: DNSProviderName is required")
	}
	if c.CacheDir == "" {
		return fmt.Errorf("tlscert: CacheDir is required")
	}
	return nil
}

func (c Config) caDirURL() string {
	if c.UseStagingCA {
		return lego.LEDirectoryStaging
	}
	return lego.LEDirectoryProduction
}

// Manager obtains and renews a certificate for Config.Domains, serving
// it via TLSConfig(). Safe for concurrent use.
type Manager struct {
	cfg    Config
	client *lego.Client

	mu      sync.RWMutex
	cert    *tls.Certificate
	certRes *certificate.Resource
}

// NewManager builds a Manager: loads or creates the ACME account,
// registers it if new, and loads or obtains a certificate from cache.
// This performs real network calls (ACME registration, and a
// certificate Obtain if none is cached) — it is not a pure/offline
// constructor.
func NewManager(cfg Config) (*Manager, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	account, err := loadOrCreateAccount(cfg.CacheDir, cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("tlscert: account: %w", err)
	}

	legoCfg := lego.NewConfig(account)
	legoCfg.CADirURL = cfg.caDirURL()

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("tlscert: creating ACME client: %w", err)
	}

	provider, err := newDNSProvider(cfg.DNSProviderName)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("tlscert: setting DNS-01 provider: %w", err)
	}

	if account.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("tlscert: registering ACME account: %w", err)
		}
		account.Registration = reg
		if err := saveAccount(cfg.CacheDir, account); err != nil {
			return nil, fmt.Errorf("tlscert: saving ACME account registration: %w", err)
		}
	}

	m := &Manager{cfg: cfg, client: client}

	if res, err := loadCert(cfg.CacheDir); err == nil {
		if cert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey); err == nil && !certExpiringSoon(cert) {
			m.mu.Lock()
			m.cert = &cert
			m.certRes = res
			m.mu.Unlock()
		}
	}

	if m.needsRenewal() {
		if err := m.obtainOrRenew(); err != nil {
			return nil, fmt.Errorf("tlscert: obtaining initial certificate: %w", err)
		}
	}

	return m, nil
}

// TLSConfig returns a *tls.Config that always serves the
// Manager's current certificate, transparently reflecting renewals
// performed by RunRenewalLoop.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: m.getCertificate}
}

func (m *Manager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, fmt.Errorf("tlscert: no certificate available")
	}
	return m.cert, nil
}

// needsRenewal reports whether no certificate is loaded yet, or the
// current one is within renewBefore of expiry.
func (m *Manager) needsRenewal() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return true
	}
	return certExpiringSoon(*m.cert)
}

func certExpiringSoon(cert tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return true
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = certcrypto.ParsePEMCertificate(certcrypto.PEMEncode(certcrypto.DERCertificateBytes(cert.Certificate[0])))
		if err != nil {
			return true
		}
	}
	return time.Until(leaf.NotAfter) < renewBefore
}

// obtainOrRenew performs the real ACME network exchange (including the
// DNS-01 challenge via the configured provider), then persists and
// swaps in the new certificate.
func (m *Manager) obtainOrRenew() error {
	m.mu.RLock()
	existing := m.certRes
	m.mu.RUnlock()

	var res *certificate.Resource
	var err error
	if existing != nil {
		res, err = m.client.Certificate.RenewWithOptions(*existing, &certificate.RenewOptions{Bundle: true})
	} else {
		certKey, keyErr := certcrypto.GeneratePrivateKey(privateKeyType)
		if keyErr != nil {
			return fmt.Errorf("tlscert: generating certificate private key: %w", keyErr)
		}
		res, err = m.client.Certificate.Obtain(certificate.ObtainRequest{
			Domains:    m.cfg.Domains,
			PrivateKey: certKey,
			Bundle:     true,
		})
	}
	if err != nil {
		return fmt.Errorf("tlscert: %w", err)
	}

	if err := saveCert(m.cfg.CacheDir, res); err != nil {
		return fmt.Errorf("tlscert: caching obtained certificate: %w", err)
	}

	cert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return fmt.Errorf("tlscert: parsing obtained certificate: %w", err)
	}

	m.mu.Lock()
	m.cert = &cert
	m.certRes = res
	m.mu.Unlock()
	return nil
}

// RunRenewalLoop checks every checkInterval whether the current
// certificate needs renewal (renewBefore its expiry) and renews it if
// so. Blocks until ctx is cancelled. Renewal failures are reported via
// onError (e.g. a slog call) rather than stopping the loop — a
// transient DNS provider outage should not need a brokerd restart to
// recover from.
func (m *Manager) RunRenewalLoop(ctx context.Context, checkInterval time.Duration, onError func(error)) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.needsRenewal() {
				if err := m.obtainOrRenew(); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}
}

// privateKeyType is fixed at EC256 (a small, fast, widely-trusted
// choice) for both the ACME account key and the certificate's own key.
const privateKeyType = certcrypto.EC256
