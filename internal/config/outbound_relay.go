package config

// OutboundRelay is brokerd's selective outbound relay configuration
// (docs/outbound-relay.md, ADR-12). Absent entirely from behavior
// unless Enabled is true, on top of each rule's own Enabled flag.
type OutboundRelay struct {
	Enabled bool
	// DryRunAllRules suppresses the final network publish for **every**
	// rule, not one feature: eligibility, packet construction and encryption
	// all still run and log. Absent in config.json means true -- the safe
	// setting must not depend on remembering to write it
	// (docs/outbound-relay.md §7).
	DryRunAllRules bool
	Targets        []RelayTarget
	Rules          []RelayRule
}

// RelayTarget is one external MQTT broker the relay can publish to
// (docs/outbound-relay.md section 3).
type RelayTarget struct {
	ID          string
	Address     string
	TLSEnabled  bool
	RootTopic   string
	ChannelName string
	// PSK is already resolved: either decode.DefaultChannelPSK[:] (the
	// "default" sentinel, never a real secret) or a real channel PSK
	// decoded from psk_env, base64, ADR-11's validation rule applied
	// the same way as internal/config.Channel.PSK.
	PSK []byte

	// Username and Password authenticate to the target broker. Both empty
	// means "connect anonymously", which is fine for a private target but
	// not for the official public server, which requires credentials
	// (docs/firmware-config.md §11A). Password is resolved from
	// password_env at load time, never stored in config.json
	// (docs/security.md §7).
	Username string
	Password string
}

// RelayRule is one whitelisted forwarding rule
// (docs/outbound-relay.md section 3).
type RelayRule struct {
	ID               string
	Enabled          bool
	SourcePortnum    string // "POSITION_APP" or "NODEINFO_APP" (whitelisted in internal/config)
	TargetID         string
	OriginScope      string // "channel_members" (default) | "own_boards_only"
	Boards           []string
	Identity         string // v1: only "real" is supported
	MinPrecisionBits uint32
	MaxPrecisionBits uint32
}

const (
	OriginScopeChannelMembers = "channel_members"
	OriginScopeOwnBoardsOnly  = "own_boards_only"
)
