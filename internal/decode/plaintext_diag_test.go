//go:build diag

package decode

import (
	"database/sql"
	"os"
	"sort"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestDiagPlaintextUplinks answers "has any board ever uplinked to this broker
// with mqtt.encryption_enabled = false" -- for the whole history, not just for
// traffic since the last restart.
//
// Why it exists: internal/broker.PlaintextChecker's plaintext_uplinks_total is
// in-memory, so it only speaks for the frames one process has seen, and it
// only exists in a build that has it. The evidence for everything before that
// is nonetheless already stored: raw_frames.payload is the unmodified MQTT
// payload (raw-frame-first, ADR-3/ADR-4), and whether the packet arrived in
// the clear is a property of those bytes -- MeshPacket's payload_variant is
// `decoded` rather than `encrypted`. So the question is answerable offline,
// retroactively, and without any channel key at all.
//
// Map reports are excluded: they are unencrypted by design
// (docs/firmware-config.md §14). Their topic carries no channel segment, so
// they are recognised by their topic rather than by their contents.
//
// A frame that arrived plaintext is indistinguishable downstream from one
// brokerd decrypted itself -- same decode_status, same text, same counters --
// which is exactly why this cannot be answered with SQL alone.
//
//	CGO_ENABLED=1 DIAG_DB=… \
//	  go test -tags diag ./internal/decode/ -run TestDiagPlaintextUplinks -v
func TestDiagPlaintextUplinks(t *testing.T) {
	dbPath := os.Getenv("DIAG_DB")
	if dbPath == "" {
		t.Fatal("DIAG_DB not set")
	}

	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("opening %s: %v", dbPath, err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(`
		SELECT board_id, channel_segment, topic, payload, received_at
		  FROM raw_frames
		 ORDER BY id;`)
	if err != nil {
		t.Fatalf("querying raw_frames: %v", err)
	}
	defer func() { _ = rows.Close() }()

	type stat struct {
		plaintext  int
		encrypted  int
		firstSeen  string
		lastSeen   string
		unparsable int
	}
	stats := map[string]*stat{}
	total, mapReports := 0, 0

	for rows.Next() {
		var boardID, channel, topic, receivedAt string
		var payload []byte
		if err := rows.Scan(&boardID, &channel, &topic, &payload, &receivedAt); err != nil {
			t.Fatalf("scanning a row: %v", err)
		}
		total++

		parsed, err := ParseTopic(topic)
		if err == nil && parsed.IsMapReport {
			mapReports++
			continue
		}

		key := boardID + " / " + channel
		s := stats[key]
		if s == nil {
			s = &stat{}
			stats[key] = s
		}

		env, err := ParseServiceEnvelope(payload)
		if err != nil {
			s.unparsable++
			continue
		}
		mp, err := ParseMeshPacket(env.PacketBytes)
		if err != nil {
			s.unparsable++
			continue
		}
		switch {
		case mp.Decoded != nil:
			s.plaintext++
			if s.firstSeen == "" {
				s.firstSeen = receivedAt
			}
			s.lastSeen = receivedAt
		case mp.Encrypted != nil:
			s.encrypted++
		default:
			s.unparsable++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating raw_frames: %v", err)
	}

	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	t.Logf("%d raw frames, %d map reports skipped (unencrypted by design)", total, mapReports)
	offenders := 0
	for _, k := range keys {
		s := stats[k]
		t.Logf("%-28s encrypted=%-7d plaintext=%-7d unparsable=%d", k, s.encrypted, s.plaintext, s.unparsable)
		if s.plaintext > 0 {
			offenders++
			t.Logf("    ^ arrived in the clear between %s and %s", s.firstSeen, s.lastSeen)
		}
	}

	// Reported, not asserted: this reads whatever database it is pointed at,
	// and a deployment that did once run with mqtt.encryption_enabled = false
	// should not have a red test forever for a fact it cannot change. The
	// number is the answer; what to do about it is docs/firmware-config.md
	// §11 A.
	if offenders == 0 {
		t.Log("no plaintext arrivals: every board that ever published held mqtt.encryption_enabled = true")
		return
	}
	t.Logf("%d board/channel pair(s) uplinked in the clear -- see docs/firmware-config.md §11 A", offenders)
	t.Log("those frames' contents were readable to anything that could read the MQTT hop; " +
		"a key rotation does not undo that, and the frames stay in raw_frames as they arrived")
}
