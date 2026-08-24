package tlscert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certificate"
)

// certMeta is the subset of certificate.Resource needed to call
// Certificate.Renew later — Resource's own PrivateKey/Certificate
// bytes are stored separately as plain PEM files (certFile/certKeyFile)
// so they can be loaded directly by tls.X509KeyPair or inspected with
// standard tools, rather than base64-in-JSON.
type certMeta struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"cert_url"`
	CertStableURL string `json:"cert_stable_url"`
}

// saveCert persists an obtained/renewed certificate.Resource to dir.
func saveCert(dir string, res *certificate.Resource) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating cache dir %s: %w", dir, err)
	}

	if err := os.WriteFile(filepath.Join(dir, certFile), res.Certificate, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", certFile, err)
	}
	if err := os.WriteFile(filepath.Join(dir, certKeyFile), res.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", certKeyFile, err)
	}

	meta := certMeta{Domain: res.Domain, CertURL: res.CertURL, CertStableURL: res.CertStableURL}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cert metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certMetaFile), b, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", certMetaFile, err)
	}
	return nil
}

// loadCert reconstructs a certificate.Resource from what saveCert
// persisted, suitable for tls.X509KeyPair and Certificate.Renew.
func loadCert(dir string) (*certificate.Resource, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, certKeyFile))
	if err != nil {
		return nil, err
	}
	metaBytes, err := os.ReadFile(filepath.Join(dir, certMetaFile))
	if err != nil {
		return nil, err
	}
	var meta certMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", certMetaFile, err)
	}

	return &certificate.Resource{
		Domain:        meta.Domain,
		CertURL:       meta.CertURL,
		CertStableURL: meta.CertStableURL,
		Certificate:   certPEM,
		PrivateKey:    keyPEM,
	}, nil
}
