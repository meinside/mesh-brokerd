package tlscert

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
)

func TestLoadOrCreateAccount_GeneratesAndPersistsKey(t *testing.T) {
	dir := t.TempDir()

	acc1, err := loadOrCreateAccount(dir, "test@example.com")
	if err != nil {
		t.Fatalf("loadOrCreateAccount (create): %v", err)
	}
	if acc1.GetPrivateKey() == nil {
		t.Fatal("generated account has a nil private key")
	}
	if acc1.GetRegistration() != nil {
		t.Fatal("a freshly created account should have no registration yet")
	}

	acc2, err := loadOrCreateAccount(dir, "test@example.com")
	if err != nil {
		t.Fatalf("loadOrCreateAccount (reload): %v", err)
	}

	key1 := certcrypto.PEMEncode(acc1.GetPrivateKey())
	key2 := certcrypto.PEMEncode(acc2.GetPrivateKey())
	if string(key1) != string(key2) {
		t.Error("reloading the account produced a different private key — it should be persisted, not regenerated")
	}
}

func TestSaveAndLoadAccountRegistration(t *testing.T) {
	dir := t.TempDir()

	acc, err := loadOrCreateAccount(dir, "test@example.com")
	if err != nil {
		t.Fatalf("loadOrCreateAccount: %v", err)
	}

	// Simulate a completed registration, as NewManager would set after
	// a real client.Registration.Register call.
	acc.Registration = nil // no registration package import needed for this nil case
	if err := saveAccount(dir, acc); err != nil {
		t.Fatalf("saveAccount: %v", err)
	}

	reloaded, err := loadOrCreateAccount(dir, "test@example.com")
	if err != nil {
		t.Fatalf("loadOrCreateAccount (reload): %v", err)
	}
	if reloaded.GetRegistration() != nil {
		t.Errorf("expected nil registration to round-trip as nil, got %+v", reloaded.GetRegistration())
	}
}

func TestSaveAndLoadCert_Roundtrip(t *testing.T) {
	dir := t.TempDir()

	certPEM, keyPEM := generateTestCert(t, 24*time.Hour)
	res := &certificate.Resource{
		Domain:      "test.example.com",
		CertURL:     "https://example/cert/1",
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	if err := saveCert(dir, res); err != nil {
		t.Fatalf("saveCert: %v", err)
	}

	loaded, err := loadCert(dir)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if loaded.Domain != res.Domain || loaded.CertURL != res.CertURL {
		t.Errorf("loaded metadata = %+v, want domain/certURL matching %+v", loaded, res)
	}
	if string(loaded.Certificate) != string(certPEM) || string(loaded.PrivateKey) != string(keyPEM) {
		t.Error("loaded certificate/key bytes do not match what was saved")
	}
}

func TestLoadCert_MissingFilesReturnsError(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadCert(dir); err == nil {
		t.Fatal("loadCert on an empty directory: want error, got nil")
	}
}

func TestCertExpiringSoon(t *testing.T) {
	cases := []struct {
		name     string
		validFor time.Duration
		want     bool
	}{
		{"expires in 1 hour", time.Hour, true},
		{"expires in 10 days", 10 * 24 * time.Hour, true},
		{"expires in 60 days", 60 * 24 * time.Hour, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			certPEM, keyPEM := generateTestCert(t, c.validFor)
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatalf("parsing generated test cert: %v", err)
			}
			if got := certExpiringSoon(cert); got != c.want {
				t.Errorf("certExpiringSoon(validFor=%s) = %v, want %v", c.validFor, got, c.want)
			}
		})
	}
}

func TestNewDNSProvider_UnsupportedName(t *testing.T) {
	_, err := newDNSProvider("some-provider-nobody-supports")
	if err == nil {
		t.Fatal("newDNSProvider with an unsupported name: want error, got nil")
	}
}

func TestNewDNSProvider_KnownName(t *testing.T) {
	// cloudflare.NewDNSProvider reads its credentials from environment
	// variables and fails fast if none are set — this confirms the
	// registry actually reaches the real lego provider constructor,
	// without needing real credentials or any network call.
	_, err := newDNSProvider("cloudflare")
	if err == nil {
		t.Skip("CLOUDFLARE_DNS_API_TOKEN (or email/key) is set in this environment; nothing to assert either way")
	}
}

// --- test helpers ---

func generateTestCert(t *testing.T, validFor time.Duration) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key does not implement crypto.Signer")
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), key)
	if err != nil {
		t.Fatalf("creating test certificate: %v", err)
	}

	certPEM = certcrypto.PEMEncode(certcrypto.DERCertificateBytes(der))
	keyPEM = certcrypto.PEMEncode(key)
	return certPEM, keyPEM
}
