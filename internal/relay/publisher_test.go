package relay

import (
	"testing"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// The publisher must actually put the target's credentials on the MQTT
// connection. The official public server rejects unauthenticated clients
// (docs/firmware-config.md §11A), and because dry_run never opens a
// connection, an omission here is invisible until the first real publish —
// where it looks like the broker refusing us rather than a missing field.
func TestPahoPublisher_AppliesTargetCredentials(t *testing.T) {
	target := config.RelayTarget{
		ID:         "public",
		Address:    "mqtt.example.org:8883",
		TLSEnabled: true,
		Username:   "meshdev",
		Password:   "large4cats",
	}
	opts := NewPahoPublisher([]config.RelayTarget{target}).clientOptionsFor(target)

	if got := opts.Username; got != "meshdev" {
		t.Errorf("Username = %q, want %q", got, "meshdev")
	}
	if got := opts.Password; got != "large4cats" {
		t.Errorf("Password was not applied to the connection options")
	}
	if len(opts.Servers) != 1 || opts.Servers[0].Scheme != "tls" {
		t.Errorf("broker URL = %v, want one tls:// server", opts.Servers)
	}
}

// A target without credentials must connect anonymously rather than
// sending empty strings, which some brokers treat as a failed login.
func TestPahoPublisher_NoCredentialsWhenUnset(t *testing.T) {
	p := NewPahoPublisher(nil)
	opts := p.clientOptionsFor(config.RelayTarget{
		ID:      "anon",
		Address: "mqtt.example.org:1883",
	})
	if opts.Username != "" || opts.Password != "" {
		t.Errorf("credentials = %q/%q, want both empty", opts.Username, opts.Password)
	}
	if len(opts.Servers) != 1 || opts.Servers[0].Scheme != "tcp" {
		t.Errorf("broker URL = %v, want one tcp:// server", opts.Servers)
	}
}
