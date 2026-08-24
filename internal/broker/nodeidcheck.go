package broker

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// NodeIDChecker cross-checks each board's configured node_id
// (docs/brokerd-config.md's boards[].node_id) against the gateway_id
// that board's own frames actually carry.
//
// Why gateway_id and not NODEINFO_APP: the obvious check would compare
// against the board's periodic NODEINFO_APP uplink, but a node's NodeInfo
// *broadcast* goes out on the primary channel
// (docs/firmware-config.md section 11), which these gateways deliberately
// never uplink -- so that payload never reaches brokerd and the check
// would never fire. Every uplinked frame, by contrast, carries the
// gateway's own "!hex" ID in both the topic and the envelope
// (docs/protocol-spec.md section 1), so the comparison is available on
// the very first frame after startup.
//
// What a mismatch means: the operator-declared node_id has drifted from
// reality (a factory reset re-assigns a node number, or the wrong ID was
// pasted into config). The consequence is silent: the outbound relay's
// origin_scope: own_boards_only compares from_node against the declared
// value (internal/relay.Engine.originMatches), so a stale value makes a
// correctly-configured rule quietly stop matching.
//
// Policy, matching internal/../permcheck.go: warn, never act. The
// warning is emitted once per (board, observed ID) pair -- an operator
// does not need the same line on every frame -- while the counter keeps
// incrementing so docs/monitoring-api.md still shows it is ongoing.
type NodeIDChecker struct {
	// declared maps board ID -> configured node_id in "!hex" form,
	// holding only boards that declared one.
	declared map[string]string

	mu         sync.Mutex
	warned     map[string]bool  // "boardID|observed" -> already logged
	mismatches map[string]int64 // board ID -> occurrences
}

// NewNodeIDChecker builds a checker for the configured boards. Boards
// without a node_id are skipped entirely (the field is optional).
func NewNodeIDChecker(boards []config.Board) *NodeIDChecker {
	declared := make(map[string]string, len(boards))
	for _, b := range boards {
		if b.HasNodeID {
			declared[b.ID] = normalizeNodeID(b.NodeID)
		}
	}
	return &NodeIDChecker{
		declared:   declared,
		warned:     make(map[string]bool),
		mismatches: make(map[string]int64),
	}
}

// Check compares one frame's gateway_id against boardID's declared
// node_id. Unknown boards, boards with no declared node_id, and frames
// with no gateway_id are ignored.
func (c *NodeIDChecker) Check(boardID, gatewayID string, log *slog.Logger) {
	if boardID == "" || gatewayID == "" {
		return
	}
	want, ok := c.declared[boardID]
	if !ok {
		return
	}
	got := normalizeNodeID(gatewayID)
	if got == want {
		return
	}

	c.mu.Lock()
	c.mismatches[boardID]++
	key := boardID + "|" + got
	first := !c.warned[key]
	c.warned[key] = true
	c.mu.Unlock()

	if first && log != nil {
		log.Warn("board node_id does not match the gateway_id its frames carry"+
			" (config may be stale; outbound_relay own_boards_only rules will not match)",
			"board_id", boardID,
			"configured_node_id", want,
			"observed_gateway_id", got)
	}
}

// Mismatches returns a copy of the per-board mismatch counters
// (docs/monitoring-api.md's board_node_id_mismatches_total).
func (c *NodeIDChecker) Mismatches() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make(map[string]int64, len(c.mismatches))
	for k, v := range c.mismatches {
		out[k] = v
	}
	return out
}

// normalizeNodeID reduces both configured and observed forms to a single
// spelling ("!hex", lower case) so "!A1B2C3D4" and "!a1b2c3d4" compare
// equal.
func normalizeNodeID(id string) string {
	return "!" + strings.ToLower(strings.TrimPrefix(id, "!"))
}
