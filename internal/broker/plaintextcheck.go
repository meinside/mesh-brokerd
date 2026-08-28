package broker

import (
	"log/slog"
	"sync"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// PlaintextChecker reports frames that arrived unencrypted on a channel
// brokerd holds a PSK for.
//
// What it catches: `mqtt.encryption_enabled` is `false` out of the box, and
// what that actually does is publish every uplinked packet to the MQTT
// server *decrypted* -- "even when your uplink channels have encryption keys
// set", as the official MQTT module documentation puts it
// (docs/firmware-config.md §11 A). The channel's PSK is still configured on
// both sides and still correct; it is simply not applied on the MQTT hop.
//
// Why it needs a checker at all: nothing about the result looks wrong.
// decode.Decode accepts the `decoded` payload variant, the frame stores as
// StatusDecoded, its text is readable, and every counter and page in
// docs/monitoring-api.md shows a healthy board. It is the same failure shape
// as lora.ignore_mqtt (docs/firmware-config.md §11 A): the deployment works
// while a protection is off. Combined with the stock public mqtt.address it
// is a plaintext leak, so "it arrived fine" is exactly the wrong conclusion.
//
// What it does not flag:
//   - map reports, which are unencrypted by design (docs/firmware-config.md
//     §14) -- their topic carries no channel segment at all;
//   - a channel with no configured PSK, where brokerd has no basis to claim
//     encryption was expected (that frame is already StatusUnknownChannel).
//
// Policy, matching NodeIDChecker and permcheck.go: warn, never act. Refusing
// the frame would destroy the only evidence of the misconfiguration, and
// re-encrypting it is not possible. The warning is emitted once per (board,
// channel) pair; the counter keeps rising so docs/monitoring-api.md's
// plaintext_uplinks_total shows it is ongoing.
//
// The counter is keyed on the *publishing* board, which is the node whose
// setting decides: mqtt.encryption_enabled only does anything on a node with
// an MQTT connection, so a non-gateway sender's own copy of the field is
// inert and the gateway that uplinked the packet is the one to look at.
type PlaintextChecker struct {
	// encrypted holds the channel names brokerd has a PSK for, i.e. the
	// channels whose frames are expected to arrive encrypted.
	encrypted map[string]struct{}

	mu      sync.Mutex
	warned  map[string]bool  // "boardID|channel" -> already logged
	uplinks map[string]int64 // board ID -> occurrences
}

// NewPlaintextChecker builds a checker for the configured channels. The map
// is the same one Decode is given (internal/config's channels[].psk_env,
// already decoded); only its keys are used, never the key material.
func NewPlaintextChecker(channels map[string][decode.PSKSize]byte) *PlaintextChecker {
	encrypted := make(map[string]struct{}, len(channels))
	for name := range channels {
		encrypted[name] = struct{}{}
	}
	return &PlaintextChecker{
		encrypted: encrypted,
		warned:    make(map[string]bool),
		uplinks:   make(map[string]int64),
	}
}

// Check inspects one decoded frame. boardID may be empty (an MQTT account
// with no matching boards[] entry), in which case the frame is counted under
// "(unknown board)" rather than dropped: which board it was matters less
// than that plaintext arrived at all.
func (c *PlaintextChecker) Check(boardID string, res *decode.Result, log *slog.Logger) {
	if res == nil || !res.ArrivedPlaintext || res.MapReport {
		return
	}
	if _, ok := c.encrypted[res.ChannelSegment]; !ok {
		return
	}

	if boardID == "" {
		boardID = "(unknown board)"
	}

	c.mu.Lock()
	c.uplinks[boardID]++
	key := boardID + "|" + res.ChannelSegment
	first := !c.warned[key]
	c.warned[key] = true
	c.mu.Unlock()

	if first && log != nil {
		log.Warn("frame arrived unencrypted on a channel with a configured PSK"+
			" (the publishing board most likely has mqtt.encryption_enabled = false,"+
			" which uplinks decrypted packets whatever the channel key)",
			"board_id", boardID,
			"channel", res.ChannelSegment,
			"gateway_id", res.GatewayID,
		)
	}
}

// PlaintextUplinks returns a copy of the per-board counters
// (docs/monitoring-api.md's plaintext_uplinks_total).
func (c *PlaintextChecker) PlaintextUplinks() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make(map[string]int64, len(c.uplinks))
	for k, v := range c.uplinks {
		out[k] = v
	}
	return out
}
