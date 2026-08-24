package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// Defaults matching docs/brokerd-config.md's key reference / ADR-5 / ADR-7.
const (
	defaultListenerMQTTAddr = ":8883"
	// Localhost-only by default: the monitoring API is meant to sit behind
	// a reverse proxy (docs/monitoring-api.md), so the safe default is
	// "not reachable from the internet unless deliberately configured"
	// rather than ":443", which both exposed it by default and needed a
	// privileged port binding.
	defaultMonitoringAddr     = "127.0.0.1:9101"
	defaultBCryptCost         = 12
	defaultFailureThreshold   = 5
	defaultBanDurationMinutes = 30
	// Bounded by default (ADR-7). Unlimited retention is available by
	// writing 0 explicitly, but it is not what an operator who never
	// thought about it should silently get.
	defaultRetentionDays = 30
)

// retentionDays resolves one retention key: absent -> the bounded default,
// explicit 0 -> unlimited, negative -> a configuration error. Negative
// values would otherwise behave as unlimited (internal/storage only deletes
// when days > 0), i.e. the exact opposite of what someone writing a
// retention limit intended.
func retentionDays(v *int, key string) (int, error) {
	if v == nil {
		return defaultRetentionDays, nil
	}
	if *v < 0 {
		return 0, fmt.Errorf("config: retention.%s: %d is negative; use a positive number of days, or 0 for unlimited", key, *v)
	}
	return *v, nil
}

// Load reads and validates a config.json file at path, resolving every
// *_env field against the current process environment. It fails fast
// (returns an error, never a partially-usable Config) on any of the
// validation rules in docs/brokerd-config.md's "Validation rules"
// section — a startup error is the intended behavior for a bad config,
// not a warning.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	var raw rawConfig
	// Reject a key this schema does not define. json.Unmarshal ignores one
	// silently, so a mistyped option -- min_intervl_seconds for
	// min_interval_seconds -- left the setting at its default while the
	// operator believed it was applied. A config file is a claim about how the
	// process will behave; a typo in it must not be answered with silence.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}

	cfg := &Config{}

	// --- listener ---
	cfg.Listener.MQTTAddr = raw.Listener.MQTTAddr
	if cfg.Listener.MQTTAddr == "" {
		cfg.Listener.MQTTAddr = defaultListenerMQTTAddr
	}
	// Rejected rather than truncated: 65536 wraps to 0, which disables the
	// read deadline entirely -- the opposite of what asking for a long floor
	// means.
	if v := raw.Listener.KeepaliveFloorSeconds; v < 0 || v > 65535 {
		return nil, fmt.Errorf("config: listener.keepalive_floor_seconds %d is out of range (0-65535; 0 disables the floor and only logs)", v)
	}
	cfg.Listener.KeepaliveFloorSeconds = uint16(raw.Listener.KeepaliveFloorSeconds)

	cfg.Listener.TLSCertDomains = raw.Listener.TLSCertDomains
	if len(cfg.Listener.TLSCertDomains) == 0 {
		return nil, fmt.Errorf("config: listener.tls_cert_domains is required")
	}
	if raw.Listener.TLSDNSProvider == "" {
		return nil, fmt.Errorf("config: listener.tls_dns_provider is required")
	}
	cfg.Listener.TLSDNSProvider = raw.Listener.TLSDNSProvider
	if raw.Listener.TLSCacheDir == "" {
		return nil, fmt.Errorf("config: listener.tls_cache_dir is required")
	}
	cfg.Listener.TLSCacheDir = raw.Listener.TLSCacheDir
	cfg.Listener.TLSUseStagingCA = raw.Listener.TLSUseStagingCA

	// --- boards ---
	if len(raw.Boards) == 0 {
		return nil, fmt.Errorf("config: boards must have at least one entry")
	}
	seenBoardIDs := map[string]bool{}
	for _, rb := range raw.Boards {
		if rb.ID == "" || rb.Username == "" {
			return nil, fmt.Errorf("config: boards[].id and boards[].username are required")
		}
		if seenBoardIDs[rb.ID] {
			return nil, fmt.Errorf("config: duplicate boards[].id %q", rb.ID)
		}
		seenBoardIDs[rb.ID] = true

		hash, err := requireEnv(rb.PasswordHashEnv, fmt.Sprintf("boards[%q].password_hash_env", rb.ID))
		if err != nil {
			return nil, err
		}

		if len(rb.ACLFilters) == 0 {
			return nil, fmt.Errorf("config: boards[%q].acl_filters is required", rb.ID)
		}
		for _, f := range rb.ACLFilters {
			if err := validateACLFilter(f); err != nil {
				return nil, fmt.Errorf("config: boards[%q]: %w", rb.ID, err)
			}
		}

		board := Board{
			ID:           rb.ID,
			Username:     rb.Username,
			PasswordHash: hash,
			ACLFilters:   rb.ACLFilters,
			NodeID:       rb.NodeID,
		}
		if rb.NodeID != "" {
			dec, err := parseNodeIDHex(rb.NodeID)
			if err != nil {
				return nil, fmt.Errorf("config: boards[%q].node_id: %w", rb.ID, err)
			}
			board.NodeIDDec = dec
			board.HasNodeID = true
		}
		cfg.Boards = append(cfg.Boards, board)
	}

	// --- channels ---
	if len(raw.Channels) == 0 {
		return nil, fmt.Errorf("config: channels must have at least one entry")
	}
	seenChannels := map[string]bool{}
	for _, rc := range raw.Channels {
		if rc.Name == "" {
			return nil, fmt.Errorf("config: channels[].name is required")
		}
		if seenChannels[rc.Name] {
			return nil, fmt.Errorf("config: duplicate channels[].name %q", rc.Name)
		}
		seenChannels[rc.Name] = true

		pskB64, err := requireEnv(rc.PSKEnv, fmt.Sprintf("channels[%q].psk_env", rc.Name))
		if err != nil {
			return nil, err
		}
		psk, err := decodeChannelPSK(pskB64)
		if err != nil {
			return nil, fmt.Errorf("config: channels[%q].psk_env: %w", rc.Name, err)
		}
		cfg.Channels = append(cfg.Channels, Channel{Name: rc.Name, PSK: psk})
	}

	// --- retention ---
	// Absent means "the operator did not choose", which defaults to a
	// bounded window: keeping raw frames and decoded messages forever is
	// both unbounded disk growth and an indefinite record of message
	// content (docs/security.md, docs/storage-schema.md §6). An explicit
	// 0 still means unlimited and is left alone — that is a choice, not an
	// omission.
	rawDays, err := retentionDays(raw.Retention.RawFramesDays, "raw_frames_days")
	if err != nil {
		return nil, err
	}
	decodedDays, err := retentionDays(raw.Retention.DecodedDays, "decoded_days")
	if err != nil {
		return nil, err
	}
	cfg.Retention.RawFramesDays = rawDays
	cfg.Retention.DecodedDays = decodedDays

	// --- auth ---
	cfg.Auth.BCryptCost = orDefault(raw.Auth.BCryptCost, defaultBCryptCost)
	cfg.Auth.FailureThreshold = orDefault(raw.Auth.FailureThreshold, defaultFailureThreshold)
	cfg.Auth.BanDurationMinutes = orDefault(raw.Auth.BanDurationMinutes, defaultBanDurationMinutes)
	cfg.Auth.IPAllowlist = raw.Auth.IPAllowlist

	// --- monitoring ---
	cfg.Monitoring.ListenAddr = raw.Monitoring.ListenAddr
	if cfg.Monitoring.ListenAddr == "" {
		cfg.Monitoring.ListenAddr = defaultMonitoringAddr
	}
	apiToken, err := requireEnv(raw.Monitoring.APITokenEnv, "monitoring.api_token_env")
	if err != nil {
		return nil, err
	}
	cfg.Monitoring.APIToken = apiToken
	cfg.Monitoring.TrustTailscaleIdentity = raw.Monitoring.TrustTailscaleIdentity
	cfg.Monitoring.TailscaleAllowedLogins = raw.Monitoring.TailscaleAllowedLogins

	// Trusting an identity header is only sound while nothing but the local
	// proxy can reach this listener, so the combination that quietly breaks
	// that premise is refused rather than warned about
	// (internal/monitor/auth.go).
	if cfg.Monitoring.TrustTailscaleIdentity && !isLoopbackAddr(cfg.Monitoring.ListenAddr) {
		return nil, fmt.Errorf("config: monitoring.trust_tailscale_identity requires monitoring.listen_addr to be a loopback address (got %q): the identity header is only trustworthy while the local Tailscale Serve proxy is the sole caller, and anyone who can reach the listener directly can set that header themselves", cfg.Monitoring.ListenAddr)
	}

	// --- storage ---
	if raw.Storage.Path == "" {
		return nil, fmt.Errorf("config: storage.path is required")
	}
	cfg.Storage.Path = raw.Storage.Path

	// --- outbound_relay ---
	outboundRelay, err := loadOutboundRelay(raw)
	if err != nil {
		return nil, err
	}
	cfg.OutboundRelay = outboundRelay

	eventHooks, err := loadEventHooks(raw, cfg.Boards)
	if err != nil {
		return nil, err
	}
	cfg.EventHooks = eventHooks

	return cfg, nil
}

// requireEnv resolves envVarName from the environment, failing fast
// (docs/brokerd-config.md's "Validation rules") if the *_env config key
// itself is empty, or the named variable is unset/empty.
func requireEnv(envVarName, fieldPath string) (string, error) {
	if envVarName == "" {
		return "", fmt.Errorf("config: %s is required", fieldPath)
	}
	v, ok := os.LookupEnv(envVarName)
	if !ok || v == "" {
		return "", fmt.Errorf("config: environment variable %s (referenced by %s) is unset or empty", envVarName, fieldPath)
	}
	return v, nil
}

// decodeChannelPSK validates a channel PSK per ADR-11: standard base64
// (with padding), decoding to exactly decode.PSKSize (32) bytes.
func decodeChannelPSK(b64 string) ([decode.PSKSize]byte, error) {
	var out [decode.PSKSize]byte
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return out, fmt.Errorf("not valid standard base64: %w", err)
	}
	if len(raw) != decode.PSKSize {
		return out, fmt.Errorf("decoded to %d bytes, want %d (ADR-11)", len(raw), decode.PSKSize)
	}
	copy(out[:], raw)
	return out, nil
}

// validateACLFilter rejects the specific dangerous case
// docs/brokerd-config.md calls out: a filter that grants everything
// ("#") or reads the broker's own internal $SYS tree, rather than
// staying scoped to the private mesh namespace.
func validateACLFilter(filter string) error {
	if filter == "#" {
		return fmt.Errorf("acl_filters entry %q grants the entire topic space; scope it to the private mesh namespace instead", filter)
	}
	if strings.HasPrefix(filter, "$") {
		return fmt.Errorf("acl_filters entry %q targets a reserved $SYS-style topic; boards must never be granted this", filter)
	}
	return nil
}

// parseNodeIDHex parses a board's configured node_id ("!hex" form, e.g.
// "!4a2d2b38") into the decimal node number stored in
// raw_frames.from_node (docs/brokerd-config.md's node_id key).
func parseNodeIDHex(nodeID string) (uint32, error) {
	h := strings.TrimPrefix(nodeID, "!")
	if h == "" {
		return 0, fmt.Errorf("empty node_id")
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("not a valid \"!hex\" node id: %w", err)
	}
	return uint32(v), nil
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// isLoopbackAddr reports whether addr's host is a loopback address. An
// empty or nameless host (":9101") is not treated as loopback: that form
// listens on every interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
