package tlscert

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
)

const (
	accountKeyFile  = "account.key"
	accountJSONFile = "account.json"
	certFile        = "cert.pem"
	certKeyFile     = "cert.key"
	certMetaFile    = "cert.json"
)

// Account implements registration.User (go-acme/lego's interface for
// the ACME account identity).
type Account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration,omitempty"`

	key crypto.PrivateKey
}

func (a *Account) GetEmail() string                        { return a.Email }
func (a *Account) GetRegistration() *registration.Resource { return a.Registration }
func (a *Account) GetPrivateKey() crypto.PrivateKey        { return a.key }

// loadOrCreateAccount loads a persisted ACME account key/registration
// from dir, or generates a new account key if none exists yet
// (registration itself still needs to happen separately — see
// NewManager).
func loadOrCreateAccount(dir, email string) (*Account, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating cache dir %s: %w", dir, err)
	}

	keyPath := filepath.Join(dir, accountKeyFile)
	keyPEM, err := os.ReadFile(keyPath)
	if err == nil {
		key, err := certcrypto.ParsePEMPrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", keyPath, err)
		}
		acc := &Account{Email: email, key: key}
		if err := loadAccountRegistration(dir, acc); err != nil {
			return nil, err
		}
		return acc, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", keyPath, err)
	}

	key, err := certcrypto.GeneratePrivateKey(privateKeyType)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %w", err)
	}
	if err := os.WriteFile(keyPath, certcrypto.PEMEncode(key), 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", keyPath, err)
	}

	return &Account{Email: email, key: key}, nil
}

func loadAccountRegistration(dir string, acc *Account) error {
	path := filepath.Join(dir, accountJSONFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // not registered yet — NewManager will register it
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}
	var stored struct {
		Registration *registration.Resource `json:"registration"`
	}
	if err := json.Unmarshal(b, &stored); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	acc.Registration = stored.Registration
	return nil
}

func saveAccount(dir string, acc *Account) error {
	path := filepath.Join(dir, accountJSONFile)
	b, err := json.MarshalIndent(acc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling account: %w", err)
	}
	return os.WriteFile(path, b, 0o600)
}
