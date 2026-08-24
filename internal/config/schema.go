package config

// rawConfig mirrors config.json's on-disk shape exactly
// (docs/brokerd-config.md's "Top-level shape") — every secret is a
// *_env field naming an environment variable, never a value.
type rawConfig struct {
	Listener struct {
		MQTTAddr        string   `json:"mqtt_addr"`
		TLSCertDomains  []string `json:"tls_cert_domains"`
		TLSDNSProvider  string   `json:"tls_dns_provider"`
		TLSCacheDir     string   `json:"tls_cache_dir"`
		TLSUseStagingCA bool     `json:"tls_use_staging_ca"`
		// int, not uint16, so an out-of-range value can be rejected
		// instead of wrapping (internal/config's loader).
		KeepaliveFloorSeconds int `json:"keepalive_floor_seconds"`
	} `json:"listener"`

	Boards []struct {
		ID              string   `json:"id"`
		Username        string   `json:"username"`
		PasswordHashEnv string   `json:"password_hash_env"`
		ACLFilters      []string `json:"acl_filters"`
		NodeID          string   `json:"node_id"`
	} `json:"boards"`

	Channels []struct {
		Name   string `json:"name"`
		PSKEnv string `json:"psk_env"`
	} `json:"channels"`

	Retention struct {
		// Pointers so "absent" is distinguishable from an explicit 0:
		// absent takes defaultRetentionDays, while an explicit 0 means
		// unlimited and must be honoured (see internal/config's loader).
		RawFramesDays *int `json:"raw_frames_days"`
		DecodedDays   *int `json:"decoded_days"`
	} `json:"retention"`

	Auth struct {
		BCryptCost         int      `json:"bcrypt_cost"`
		FailureThreshold   int      `json:"failure_threshold"`
		BanDurationMinutes int      `json:"ban_duration_minutes"`
		IPAllowlist        []string `json:"ip_allowlist"`
	} `json:"auth"`

	Monitoring struct {
		ListenAddr  string `json:"listen_addr"`
		APITokenEnv string `json:"api_token_env"`
		// Accept a Tailscale Serve identity header instead of the token for
		// the HTML page. Off unless stated, since it trusts a header.
		TrustTailscaleIdentity bool     `json:"trust_tailscale_identity"`
		TailscaleAllowedLogins []string `json:"tailscale_allowed_logins"`
	} `json:"monitoring"`

	Storage struct {
		Path string `json:"path"`
	} `json:"storage"`

	OutboundRelay struct {
		Enabled bool `json:"enabled"`
		// Pointer so "absent" is distinguishable from an explicit false:
		// absent must mean "suppressed", never "publish for real".
		DryRunAllRules *bool `json:"dry_run_all_rules"`
		// DryRunLegacy catches the pre-rename key so it fails loudly
		// instead of being ignored (internal/config's loader).
		DryRunLegacy *bool `json:"dry_run"`
		Targets      []struct {
			ID          string `json:"id"`
			Address     string `json:"address"`
			TLSEnabled  bool   `json:"tls_enabled"`
			RootTopic   string `json:"root_topic"`
			ChannelName string `json:"channel_name"`
			PSK         string `json:"psk"`
			// Username/PasswordEnv are optional, but the official public
			// server requires both (docs/firmware-config.md §11A). Password
			// is named, never valued, here — docs/security.md §7.
			Username    string `json:"username"`
			PasswordEnv string `json:"password_env"`
		} `json:"targets"`
		Rules []struct {
			ID            string   `json:"id"`
			Enabled       bool     `json:"enabled"`
			SourcePortnum string   `json:"source_portnum"`
			Target        string   `json:"target"`
			OriginScope   string   `json:"origin_scope"`
			Boards        []string `json:"boards"`
			Identity      string   `json:"identity"`
			Eligibility   struct {
				MinPrecisionBits *uint32 `json:"min_precision_bits"`
				MaxPrecisionBits *uint32 `json:"max_precision_bits"`
			} `json:"eligibility"`
		} `json:"rules"`
	} `json:"outbound_relay"`

	EventHooks struct {
		Enabled bool `json:"enabled"`
		// Pointer so "absent" is distinguishable from an explicit false:
		// absent must mean "suppressed", never "fire for real" -- the same
		// reasoning as outbound_relay.dry_run_all_rules.
		DryRun        *bool           `json:"dry_run"`
		QueueSize     int             `json:"queue_size"`
		MaxConcurrent int             `json:"max_concurrent"`
		Targets       []rawHookTarget `json:"targets"`
	} `json:"event_hooks"`
}

// rawHookTarget mirrors one event_hooks.targets[] entry
// (docs/event-hooks.md). Named rather than anonymous so the loader's tests
// can build one.
type rawHookTarget struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`

	URLEnv        string            `json:"url_env"`
	SecretEnv     string            `json:"secret_env"`
	AllowUnsigned bool              `json:"allow_unsigned"`
	Headers       map[string]string `json:"headers"`

	Command string   `json:"command"`
	Args    []string `json:"args"`

	TimeoutSeconds       int    `json:"timeout_seconds"`
	Retries              *int   `json:"retries"`
	DisableAfterFailures *int   `json:"disable_after_failures"`
	MinIntervalSeconds   int    `json:"min_interval_seconds"`
	DedupeWindowSeconds  int    `json:"dedupe_window_seconds"`
	QuietHours           string `json:"quiet_hours"`
	Template             string `json:"template"`

	Match struct {
		Events            []string `json:"events"`
		Portnums          []string `json:"portnums"`
		Channels          []string `json:"channels"`
		Boards            []string `json:"boards"`
		IncludeText       bool     `json:"include_text"`
		IncludeRawPayload bool     `json:"include_raw_payload"`
		ExcludeOwnBoards  bool     `json:"exclude_own_boards"`
	} `json:"match"`
}
