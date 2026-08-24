package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// A generated hash must verify against the password it was made from, and
// must carry the cost that was asked for.
//
// The cost matters because it is the one thing about a bcrypt hash that
// cannot be changed afterwards: verification reads it back out of the hash,
// so `auth.bcrypt_cost` in config.json can only ever describe what was used
// at generation time (docs/security.md §3).
func TestGenerateBcrypt(t *testing.T) {
	const password = "correct-horse-battery-staple"

	hash, err := generateBcrypt(password, 10)
	if err != nil {
		t.Fatalf("generateBcrypt: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Errorf("generated hash does not verify against its own password: %v", err)
	}
	if got, err := bcrypt.Cost([]byte(hash)); err != nil || got != 10 {
		t.Errorf("cost = %d (err %v), want 10", got, err)
	}
	if strings.Contains(hash, password) {
		t.Error("hash contains the plaintext password")
	}
}

// An empty password is a mistake, not a valid credential.
func TestGenerateBcrypt_RejectsEmpty(t *testing.T) {
	if _, err := generateBcrypt("", 12); err == nil {
		t.Error("an empty password was accepted")
	}
}

// bcrypt silently ignores anything past 72 bytes, so a longer password is
// not the password the operator thinks it is.
func TestGenerateBcrypt_RejectsOverLongPassword(t *testing.T) {
	if _, err := generateBcrypt(strings.Repeat("a", 73), 12); err == nil {
		t.Error("a 73-byte password was accepted; bcrypt ignores bytes past 72")
	}
}

// A channel PSK must be exactly the size ADR-11 requires, in the encoding
// the Meshtastic app and brokerd both expect.
func TestGeneratePSK(t *testing.T) {
	a, err := generatePSK()
	if err != nil {
		t.Fatalf("generatePSK: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("PSK is not standard base64 with padding: %v", err)
	}
	if len(raw) != decode.PSKSize {
		t.Errorf("PSK is %d bytes, want %d (ADR-11)", len(raw), decode.PSKSize)
	}

	b, err := generatePSK()
	if err != nil {
		t.Fatalf("generatePSK: %v", err)
	}
	if a == b {
		t.Error("two calls produced the same PSK")
	}
}

func TestGenerateToken(t *testing.T) {
	a, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	// Long enough that guessing it is not a strategy, and URL-safe so it
	// survives being pasted into a header or a shell without quoting games.
	if len(a) < 32 {
		t.Errorf("token is %d characters, want at least 32", len(a))
	}
	if strings.ContainsAny(a, "+/=") {
		t.Errorf("token %q is not URL-safe", a)
	}

	b, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if a == b {
		t.Error("two calls produced the same token")
	}
}
