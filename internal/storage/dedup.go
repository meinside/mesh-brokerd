package storage

import (
	"fmt"
	"time"
)

// DedupWindow is how far back IsDuplicate looks for an earlier delivery
// of the same (gateway_id, packet_id) pair (ADR-14, docs/adr.md).
//
// Rationale for 5 minutes: real firmware was observed re-delivering an
// identical packet three times at ~7-8 second intervals during this
// project's first board integration test, so the window has to comfortably
// exceed firmware retry/reconnect timing.
//
// The window alone is not sufficient, and cannot be made so: a gateway
// re-publishes a queued packet when it reconnects, and what makes it reconnect
// is often brokerd restarting, which no window can bound. Byte identity covers
// that case at any age -- see IsDuplicate.
//
// It stays bounded because Meshtastic packet IDs are random 32-bit
// values -- two genuinely distinct packets colliding on (gateway_id,
// packet_id) inside five minutes is not a practical concern, while an
// unbounded window would suppress a legitimate re-delivery days later
// carrying different bytes (which docs/storage-schema.md's non-UNIQUE dedup
// index deliberately allows).
//
// Deliberately a constant rather than a config key: this tracks firmware
// retry behavior, not deployment-specific volume, so there is no known
// reason for an operator to tune it. Promote it to
// docs/brokerd-config.md if real evidence ever appears.
const DedupWindow = 5 * time.Minute

// IsDuplicate reports whether this delivery has already been recorded, by
// either of two rules (ADR-14, docs/protocol-spec.md section 2):
//
//  1. the same (gateway_id, packet_id) arrived within DedupWindow -- a firmware
//     retry, whose bytes may differ from the original in hop_limit and the
//     reception fields;
//  2. the same (gateway_id, packet_id) arrived with a **byte-identical**
//     payload, however long ago.
//
// The second rule exists because one text message was stored, shown and
// notified twice. Restarting brokerd made a gateway reconnect,
// and the firmware re-published the packet still in its queue 5m48s after the
// original -- outside the window, and identical to the byte, ciphertext
// included. Widening the window would only narrow that hole: the delay is
// however long the operator waits between restarts.
//
// Byte identity is safe to apply with no time bound. Packet ids are random
// 32-bit values, so two distinct packets sharing an id *and* their ciphertext
// and nonce is not a case that occurs; and both rules use the existing
// (gateway_id, packet_id) index, so neither costs a scan.
//
// A packet id of 0 means the packet **did not state one** -- not that its id
// is zero (ADR-15's rule, here too). Such a frame never participates in
// dedup: `MAP_REPORT_APP` carries no packet id at all
// (docs/firmware-config.md §14), so keying on 0 made every id-less frame
// from one gateway a duplicate of the previous one. Four real map reports
// were suppressed that way, and because the worker skips the outbound relay
// for a duplicate, they were never relayed either.
//
// Callers must additionally skip this check when the packet's gateway id or
// packet id could not be parsed -- an unparsed packet has no usable
// identity, and treating every such frame as a duplicate of the others
// would discard real data.
func (s *Store) IsDuplicate(gatewayID string, packetID uint32, payload []byte, now time.Time) (bool, error) {
	if gatewayID == "" || packetID == 0 {
		return false, nil
	}

	cutoff := now.Add(-DedupWindow).UTC().Format(time.RFC3339)

	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM raw_frames
		  WHERE gateway_id = ? AND packet_id = ?
		    AND (received_at >= ? OR payload = ?);`,
		gatewayID, int64(packetID), cutoff, payload,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("storage: dedup lookup: %w", err)
	}
	return count > 0, nil
}
