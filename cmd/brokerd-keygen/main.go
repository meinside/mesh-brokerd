// Command brokerd-keygen generates the secret values `.env` holds by name
// (docs/security.md §7): a board account's bcrypt hash, a channel PSK, and
// the monitoring API token.
//
// It exists because none of these can be produced with what a plain server
// has installed. bcrypt needs a library — `openssl passwd` cannot do it,
// `htpasswd` is part of an Apache package, and Python's bcrypt is a separate
// install — while this repository already depends on
// golang.org/x/crypto/bcrypt. The previous instruction in `.env.sample`
// pointed at a `-tags tools` target that never existed and silently ran
// `brokerd` itself instead.
//
// Nothing here reads or writes `.env`: values are printed for the operator to
// place, so a mistake cannot overwrite a working secret.
//
//	go run ./cmd/brokerd-keygen -psk
//	go run ./cmd/brokerd-keygen -token
//	go run ./cmd/brokerd-keygen -bcrypt            # prompts on stdin
//	go run ./cmd/brokerd-keygen -bcrypt -cost 12
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// bcryptMaxPasswordBytes is bcrypt's own input limit. Anything longer is
// silently ignored by the algorithm, so accepting it would hand back a hash
// for a password the operator did not choose.
const bcryptMaxPasswordBytes = 72

func main() {
	var (
		doBcrypt = flag.Bool("bcrypt", false, "hash a board account password read from stdin (docs/security.md section 3)")
		doPSK    = flag.Bool("psk", false, "generate a channel PSK: 32 random bytes, standard base64 (ADR-11)")
		doToken  = flag.Bool("token", false, "generate a monitoring API bearer token (docs/monitoring-api.md section 2)")
		cost     = flag.Int("cost", bcrypt.DefaultCost+2, "bcrypt cost; keep in step with auth.bcrypt_cost in config.json")
	)
	flag.Parse()

	n := 0
	for _, b := range []bool{*doBcrypt, *doPSK, *doToken} {
		if b {
			n++
		}
	}
	if n != 1 {
		fmt.Fprintln(os.Stderr, "brokerd-keygen: pass exactly one of -bcrypt, -psk, -token")
		flag.Usage()
		os.Exit(2)
	}

	var (
		out string
		err error
	)
	switch {
	case *doPSK:
		out, err = generatePSK()
	case *doToken:
		out, err = generateToken()
	case *doBcrypt:
		var pw string
		pw, err = readPassword()
		if err == nil {
			out, err = generateBcrypt(pw, *cost)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "brokerd-keygen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

// readPassword reads one line from stdin. Prompting on stderr keeps stdout
// clean so the result can be piped.
func readPassword() (string, error) {
	fmt.Fprint(os.Stderr, "password (will be echoed): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func generateBcrypt(password string, cost int) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	if len(password) > bcryptMaxPasswordBytes {
		return "", fmt.Errorf("password is %d bytes; bcrypt ignores everything past %d, so the hash would not match the password you chose",
			len(password), bcryptMaxPasswordBytes)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hashing: %w", err)
	}
	return string(h), nil
}

// generatePSK returns a channel PSK in the exact form the Meshtastic app and
// CLI accept, so it can be pasted into both sides unchanged (ADR-11).
func generatePSK() (string, error) {
	b := make([]byte, decode.PSKSize)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// generateToken returns a URL-safe token, so it survives being pasted into an
// Authorization header, a shell, or a .env line without quoting concerns.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
