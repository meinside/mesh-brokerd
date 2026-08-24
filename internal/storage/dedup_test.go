package storage

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

func insertFrameAt(t *testing.T, s *Store, gatewayID string, packetID uint32, at time.Time) {
	t.Helper()
	insertFramePayloadAt(t, s, gatewayID, packetID, []byte{0x01}, at)
}

func insertFramePayloadAt(t *testing.T, s *Store, gatewayID string, packetID uint32, payload []byte, at time.Time) {
	t.Helper()
	res := &decode.Result{
		Topic:          "msh/pvt/2/e/pvt/" + gatewayID,
		ChannelSegment: "pvt",
		GatewayID:      gatewayID,
		PacketID:       packetID,
		FromNode:       0x11223344,
		Status:         decode.StatusDecoded,
		PacketParsed:   true,
	}
	if _, err := s.InsertRawFrame(res, "alpha", "alpha", payload, at); err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
}

func TestIsDuplicate_DetectsRecentSameKey(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	// The real observed case: same gateway_id + packet_id re-delivered
	// ~8 seconds later (docs/firmware-config.md's integration-test note).
	insertFrameAt(t, s, "!11223344", 1573662254, now.Add(-8*time.Second))

	dup, err := s.IsDuplicate("!11223344", 1573662254, []byte{0x01}, now)
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if !dup {
		t.Error("IsDuplicate = false, want true for the same key 8s earlier")
	}
}

func TestIsDuplicate_DifferentPacketIDIsNotDuplicate(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	insertFrameAt(t, s, "!11223344", 1573662254, now.Add(-8*time.Second))

	dup, err := s.IsDuplicate("!11223344", 999999, []byte{0x01}, now)
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if dup {
		t.Error("IsDuplicate = true for a different packet_id, want false")
	}
}

func TestIsDuplicate_DifferentGatewayIsNotDuplicate(t *testing.T) {
	// Two boards gatewaying the same mesh packet are *distinct*
	// deliveries by this compound key -- that is the point of keying on
	// gateway_id as well (docs/protocol-spec.md section 2).
	s := openTestStore(t)
	now := time.Now()
	insertFrameAt(t, s, "!11223344", 1573662254, now.Add(-8*time.Second))

	dup, err := s.IsDuplicate("!99aabbcc", 1573662254, []byte{0x01}, now)
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if dup {
		t.Error("IsDuplicate = true for a different gateway_id, want false")
	}
}

func TestIsDuplicate_OutsideWindowWithDifferentBytesIsNotDuplicate(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	// Just outside DedupWindow, and carrying different bytes: a packet id can
	// legitimately be reused this much later, so the frame is kept, matching
	// the non-UNIQUE index rationale in docs/storage-schema.md section 3.
	//
	// This test used to reuse the same payload as well, which the byte-identity
	// rule below now (correctly) calls a duplicate. Only the different-bytes
	// half of what it asserted is still true.
	insertFramePayloadAt(t, s, "!11223344", 1573662254, []byte{0x01}, now.Add(-DedupWindow-time.Minute))

	dup, err := s.IsDuplicate("!11223344", 1573662254, []byte{0x02, 0x03}, now)
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if dup {
		t.Errorf("IsDuplicate = true for a delivery older than DedupWindow (%s), want false", DedupWindow)
	}
}

func TestIsDuplicate_EmptyDatabase(t *testing.T) {
	s := openTestStore(t)
	dup, err := s.IsDuplicate("!11223344", 1573662254, []byte{0x01}, time.Now())
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if dup {
		t.Error("IsDuplicate = true against an empty database, want false")
	}
}

func TestIsDuplicate_UsesDedupIndex(t *testing.T) {
	// Confirms the query actually uses idx_raw_frames_dedup rather than
	// scanning -- docs/storage-schema.md section 3 exists for this query
	// specifically, so a plan regression should be caught here.
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "plan.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	rows, err := s.DB().Query(
		`EXPLAIN QUERY PLAN
		 SELECT COUNT(*) FROM raw_frames
		  WHERE gateway_id = ? AND packet_id = ? AND received_at >= ?;`,
		"!11223344", 1, "2026-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var plan string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scanning plan: %v", err)
		}
		plan += detail + "\n"
	}
	if !strings.Contains(plan, "idx_raw_frames_dedup") {
		t.Errorf("dedup query does not use idx_raw_frames_dedup; plan was:\n%s", plan)
	}
}

// TestIsDuplicate_PacketIDZeroNeverDeduplicates is the regression test for a
// bug that reached production: MAP_REPORT_APP carries no packet id, so every
// id-less frame from one gateway looked like a duplicate of the previous one.
// Four real map reports were marked duplicate in the live database, and
// because the worker skips the outbound relay for a duplicate, they were
// never relayed either.
//
// 0 means "the packet did not state an id", which is not an identity to
// compare (ADR-15's rule).
func TestIsDuplicate_PacketIDZeroNeverDeduplicates(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	first := &decode.Result{
		Topic: "msh/pvt/2/map/", ChannelSegment: "LongFast",
		GatewayID: "!11223344", PacketID: 0, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumMapReport, PacketParsed: true,
	}
	if _, err := s.InsertRawFrame(first, "alpha", "alpha", []byte{0x01}, now); err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}

	// A second id-less frame from the same gateway, seconds later: distinct
	// traffic, not a re-delivery.
	dup, err := s.IsDuplicate("!11223344", 0, []byte{0x01}, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if dup {
		t.Error("a frame with no packet id was reported as a duplicate")
	}

	// A real packet id still deduplicates.
	real := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 4093269443, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage, PacketParsed: true,
		TextMessage: &decode.TextMessage{Text: "x"},
	}
	if _, err := s.InsertRawFrame(real, "alpha", "alpha", []byte{0x02}, now); err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	dup, err = s.IsDuplicate("!11223344", 4093269443, []byte{0x01}, now.Add(8*time.Second))
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if !dup {
		t.Error("a re-delivery of the same packet id was not reported as a duplicate")
	}
}

// TestIsDuplicate_EmptyGatewayNeverDeduplicates keeps the other half of the
// identity rule inside the function, so no caller can forget it.
func TestIsDuplicate_EmptyGatewayNeverDeduplicates(t *testing.T) {
	s := openTestStore(t)
	dup, err := s.IsDuplicate("", 12345, []byte{0x01}, time.Now())
	if err != nil {
		t.Fatalf("IsDuplicate: %v", err)
	}
	if dup {
		t.Error("a frame with no gateway id was reported as a duplicate")
	}
}

// TestIsDuplicate_ByteIdenticalReDeliveryIsDuplicateAtAnyAge covers a real
// duplicate the 5-minute window let through, observed live: one text
// message appeared twice on the monitoring page and notified twice.
//
// Restarting brokerd makes a gateway reconnect, and on reconnect the firmware
// re-published the packet still in its queue -- 5m48s after the original, so
// outside the window. The two frames were identical to the byte, ciphertext and
// all: same gateway, same packet id, same nonce.
//
// A window is the right tool for a retry whose bytes differ. It cannot bound
// this, because what delayed the re-publish was our own maintenance and no
// window covers an arbitrary restart. Byte identity settles it instead: packet
// ids are random 32-bit values, so two distinct packets sharing an id *and*
// their ciphertext is not a case that occurs.
func TestIsDuplicate_ByteIdenticalReDeliveryIsDuplicateAtAnyAge(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	payload := []byte{0x0a, 0x41, 0x0d, 0x00, 0xb3, 0xa5, 0x1b, 0x15, 0xff}

	for _, age := range []time.Duration{
		DedupWindow + 48*time.Second, // the observed gap
		2 * time.Hour,
		72 * time.Hour,
	} {
		s := s
		insertFramePayloadAt(t, s, "!11223344", 116742102, payload, now.Add(-age))
		dup, err := s.IsDuplicate("!11223344", 116742102, payload, now)
		if err != nil {
			t.Fatalf("IsDuplicate: %v", err)
		}
		if !dup {
			t.Errorf("a byte-identical re-delivery %s later was not called a duplicate", age)
		}
	}
}
