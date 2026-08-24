// Package config loads and validates brokerd's config.json plus the
// environment-variable-sourced secrets it references
// (docs/brokerd-config.md, docs/security.md §7). Structural config
// (accounts, ACLs, channel names, retention, listener addresses) lives
// in config.json; every secret value (passwords, PSKs, tokens) is
// resolved from a named environment variable at load time — never
// written into config.json itself.
package config

import (
	"github.com/meinside/mesh-brokerd/internal/decode"
)

// Config is the fully loaded and validated brokerd configuration
// (docs/brokerd-config.md's "Top-level shape"). Secret fields hold the
// already-resolved value (decoded PSK bytes, bcrypt hash string, bearer
// token string) — never the env var name past this package.
type Config struct {
	Listener      Listener
	Boards        []Board
	Channels      []Channel
	Retention     Retention
	Auth          Auth
	Monitoring    Monitoring
	Storage       Storage
	OutboundRelay OutboundRelay
	EventHooks    EventHooks
}

type Listener struct {
	MQTTAddr       string
	TLSCertDomains []string

	// TLS certificate management (ADR-8, docs/adr.md). The DNS-01
	// provider's own credentials are read directly from its
	// conventional environment variables by internal/tlscert/lego —
	// never referenced indirectly via a config.json *_env key, since
	// lego's providers each expect a fixed env var name they choose
	// (see internal/tlscert's package doc).
	TLSDNSProvider  string
	TLSCacheDir     string
	TLSUseStagingCA bool

	// KeepaliveFloorSeconds raises a client's advertised MQTT keepalive to
	// at least this value, which lengthens mochi-mqtt's read deadline
	// (keepalive * 1.5, [MQTT-3.1.2-22]). 0 -- the default -- leaves every
	// client's own value alone and only logs it, which is how to measure
	// before choosing a floor (internal/broker.KeepaliveFloorHook).
	KeepaliveFloorSeconds uint16
}

type Board struct {
	ID           string
	Username     string
	PasswordHash string // resolved from password_hash_env (bcrypt hash, not plaintext)
	ACLFilters   []string
	NodeID       string // optional, "!hex" form as configured
	NodeIDDec    uint32 // NodeID parsed to decimal once at load time (docs/brokerd-config.md)
	HasNodeID    bool
}

type Channel struct {
	Name string
	PSK  [decode.PSKSize]byte // resolved+base64-decoded from psk_env (ADR-11)
}

type Retention struct {
	RawFramesDays int
	DecodedDays   int
}

type Auth struct {
	// BCryptCost is advisory: bcrypt embeds its cost in every hash, so
	// verification uses whatever cost a hash was created with and this value
	// cannot change it. It records the intended cost, which
	// cmd/brokerd-keygen applies at generation time
	// (docs/brokerd-config.md).
	BCryptCost         int
	FailureThreshold   int
	BanDurationMinutes int
	IPAllowlist        []string
}

type Monitoring struct {
	ListenAddr string
	APIToken   string // resolved from api_token_env

	// TrustTailscaleIdentity lets the HTML page authenticate a request by
	// the identity header a Tailscale Serve proxy injects, instead of the
	// token — the only way a browser reaches the page without a credential
	// prompt. Off unless the config says otherwise: it trusts a header, and
	// that is only sound while nothing but the local proxy can reach the
	// listener (internal/monitor/auth.go).
	TrustTailscaleIdentity bool
	// TailscaleAllowedLogins restricts which logins that path accepts.
	// Empty means any tailnet user who can reach the proxy.
	TailscaleAllowedLogins []string
}

type Storage struct {
	Path string
}

// ChannelPSKs returns a name -> PSK lookup suitable for
// internal/decode.Decode's channels argument.
func (c *Config) ChannelPSKs() map[string][decode.PSKSize]byte {
	m := make(map[string][decode.PSKSize]byte, len(c.Channels))
	for _, ch := range c.Channels {
		m[ch.Name] = ch.PSK
	}
	return m
}
