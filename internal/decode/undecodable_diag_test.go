//go:build diag

package decode

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestDiagUndecodableFrames answers "what portnums are hiding in the frames
// this deployment cannot decrypt".
//
// A frame stored as decrypt_failed has no portnum, because the portnum lives
// inside the encrypted Data submessage. Every query about "did we ever receive
// a NODEINFO" is therefore blind to those frames, and reading an empty result
// as "it was never sent" is the mistake this test exists to prevent.
//
// It tries every PSK it is given against every stored failure, so a deployment
// that has rotated a channel key -- and still has the old key in its
// environment -- can find out what it lost. Keys come from the environment and
// are never printed.
//
//	CGO_ENABLED=1 DIAG_DB=… DIAG_PSKS=base64,base64 \
//	  go test -tags diag ./internal/decode/ -run TestDiagUndecodableFrames -v
func TestDiagUndecodableFrames(t *testing.T) {
	var psks [][PSKSize]byte
	for _, raw := range strings.Split(os.Getenv("DIAG_PSKS"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			t.Fatalf("DIAG_PSKS entry is not base64: %v", err)
		}
		if len(decoded) != PSKSize {
			t.Fatalf("a PSK is %d bytes, want %d", len(decoded), PSKSize)
		}
		var psk [PSKSize]byte
		copy(psk[:], decoded)
		psks = append(psks, psk)
	}
	if len(psks) == 0 {
		t.Fatal("DIAG_PSKS not set")
	}

	db := openDiagDB(t)
	defer func() { _ = db.Close() }()

	rows, err := db.Query(
		`SELECT id, received_at, board_id, channel_segment, topic, payload
		   FROM raw_frames
		  WHERE decode_status = 'decrypt_failed'
		  ORDER BY id;`)
	if err != nil {
		t.Fatalf("querying failures: %v", err)
	}
	defer func() { _ = rows.Close() }()

	counts := map[string]int{}
	total := 0
	for rows.Next() {
		var (
			id                           int64
			receivedAt, board, ch, topic string
			payload                      []byte
		)
		if err := rows.Scan(&id, &receivedAt, &board, &ch, &topic, &payload); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		total++

		// Try each key against the frame, whatever channel the topic names.
		outcome := "still undecodable"
		for i, psk := range psks {
			res, err := Decode(topic, payload, map[string][PSKSize]byte{ch: psk})
			if err != nil || res == nil || res.Status != StatusDecoded {
				continue
			}
			outcome = fmt.Sprintf("psk[%d] -> %s", i, res.Portnum.Name())
			if res.Portnum == PortNumNodeInfo && res.NodeInfo != nil {
				// Lengths only: a node's name is not this project's to print.
				outcome += fmt.Sprintf(" (long_name %d chars, short_name %d chars)",
					len([]rune(res.NodeInfo.LongName)), len([]rune(res.NodeInfo.ShortName)))
			}
			break
		}
		counts[outcome]++
		t.Logf("frame %d  %s  via %s  channel %s  -> %s", id, receivedAt, board, ch, outcome)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating: %v", err)
	}

	t.Logf("--- %d undecodable frames ---", total)
	for outcome, n := range counts {
		t.Logf("  %3d  %s", n, outcome)
	}
}
