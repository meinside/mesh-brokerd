package storage

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// ReprocessReport summarises what a reprocessing pass did (or, in a dry
// run, would do).
type ReprocessReport struct {
	Scanned             int
	FieldsUpdated       int
	DecodedRowsInserted int
	DecodedRowsSkipped  int
	Failed              int
	// Regressions names frames left untouched because today's decode is worse
	// than what is stored -- almost always a rotated channel key.
	Regressions []string

	// StatusChangeIDs names every frame whose diagnosis changed, so a
	// transition can be looked at rather than only counted.
	StatusChangeIDs []string

	// StatusChanges counts transitions as "old->new". A frame stored
	// before a decoder existed reads unhandled_portnum and becomes decoded;
	// that is a change in recorded fact, not a cosmetic one, so it is
	// reported rather than applied quietly.
	StatusChanges map[string]int
	BackupPath    string
}

// reprocessRow is one frame's stored input.
type reprocessRow struct {
	id      int64
	topic   string
	payload []byte
	status  string
}

// Reprocess re-decodes every stored frame from raw_frames.payload and fills
// in what the current decoder understands: the MeshPacket/Data columns and
// a decoded_payloads row (docs/storage-schema.md §7). This is what makes
// columns added later meaningful for frames that arrived earlier — the
// bytes were always kept for exactly this (ADR-3's raw-frame-first
// principle).
//
// Rules it follows, and why:
//
//   - apply=false changes nothing and reports what would happen. The
//     default has to be the harmless one.
//   - Before writing, a copy of the database is made with VACUUM INTO, so a
//     bulk rewrite of every row is never the only version that exists.
//   - text_messages is left alone. Retention may have deleted rows there
//     deliberately, and re-creating them would undo a deletion the operator
//     asked for.
//   - For the same reason, no decoded_payloads row is inserted for a frame
//     older than the decoded retention window; the raw columns are still
//     updated, since those are part of the raw record.
//   - A frame that still fails to decode is left exactly as it was,
//     including its decode_status: a stored diagnosis is worth more than an
//     overwritten one.
//   - Duplicate suppression is **recomputed** with the live rule
//     (IsDuplicate against earlier stored frames), not carried over. Running
//     the same rule in both paths is what keeps them from disagreeing: a
//     genuine re-delivery stays duplicate and writes no decoded row (ADR-14),
//     while frames wrongly marked duplicate by the packet-id-zero bug become
//     decoded again.
//   - Each row is decoded inside a recover(), so one malformed payload
//     cannot abort a pass over hundreds of others.
func (s *Store) Reprocess(channels map[string][decode.PSKSize]byte, decodedDays int, apply bool, log *slog.Logger) (ReprocessReport, error) {
	if log == nil {
		log = slog.Default()
	}
	report := ReprocessReport{StatusChanges: map[string]int{}}

	rows, err := s.collectReprocessRows()
	if err != nil {
		return report, err
	}
	report.Scanned = len(rows)

	var decodedCutoff string
	if decodedDays > 0 {
		decodedCutoff = time.Now().UTC().AddDate(0, 0, -decodedDays).Format(time.RFC3339)
	}

	if apply {
		path, err := s.backupBeforeReprocess()
		if err != nil {
			return report, err
		}
		report.BackupPath = path
		log.Info("reprocess: database copied before writing", "backup", path, "rows", len(rows))
	}

	for _, row := range rows {
		res, decodeErr := safeDecode(row.topic, row.payload, channels)
		if decodeErr != nil || res == nil {
			report.Failed++
			log.Debug("reprocess: frame could not be decoded", "raw_frame_id", row.id, "error", decodeErr)
			continue
		}

		// Re-apply dedup exactly as the live path does, using the frames
		// stored before this one.
		if res.Status == decode.StatusDecoded {
			dup, err := s.isDuplicateAmongEarlier(row.id, res.GatewayID, res.PacketID)
			if err != nil {
				return report, err
			}
			if dup {
				res.Status = decode.StatusDuplicate
			}
		}

		// A pass that can no longer reproduce a fact must not erase it.
		//
		// A frame stored as decoded was decrypted with the key in use at the
		// time. Rotating a channel's PSK makes today's decode of that frame
		// fail, and overwriting the row would replace a real portnum, SNR and
		// payload with NULLs that nothing can recover -- the frame's ciphertext
		// is still there, but the key that opened it is gone. Reprocessing is
		// for improving a diagnosis, not for forgetting one.
		if row.status == string(decode.StatusDecoded) && res.Status != decode.StatusDecoded {
			report.Regressions = append(report.Regressions,
				fmt.Sprintf("frame %d: %s would become %s; kept", row.id, row.status, res.Status))
			continue
		}

		if string(res.Status) != row.status {
			report.StatusChanges[row.status+"->"+string(res.Status)]++
			// Name the frame, not just the transition. An aggregate count of
			// "decoded->decrypt_failed" says something got worse without
			// saying what, which is not enough to decide whether to apply the
			// pass: reprocessing rewrites the diagnosis a stored frame
			// carries, so every change has to be explainable first.
			report.StatusChangeIDs = append(report.StatusChangeIDs,
				fmt.Sprintf("frame %d: %s->%s", row.id, row.status, res.Status))
		}

		// A duplicate keeps its raw columns but never gets a decoded row
		// (ADR-14): re-delivery is a fact about transport, not new content.
		if res.Status == decode.StatusDuplicate {
			report.FieldsUpdated++
			if apply {
				if err := s.applyReprocessedRow(row.id, res, false, &report); err != nil {
					return report, err
				}
			}
			continue
		}

		// A frame that decodes to nothing usable is left as stored: its
		// existing decode_status is the diagnosis, and overwriting it would
		// replace evidence with a fresh guess.
		if res.Status != decode.StatusDecoded && res.Status != decode.StatusUnhandledPortnum {
			continue
		}

		report.FieldsUpdated++

		insertDecoded := false
		if _, ok := res.DecodedFields(); ok {
			insertDecoded = true
			if decodedCutoff != "" {
				withinWindow, err := s.frameWithinWindow(row.id, decodedCutoff)
				if err != nil {
					return report, err
				}
				if !withinWindow {
					insertDecoded = false
					report.DecodedRowsSkipped++
				}
			}
		}

		if !apply {
			// Predict what apply would actually do. A dry run that counts
			// every decodable frame reports rows it would not insert -- one
			// pass predicted 118 and inserted 1, because 117 were already
			// there from an earlier pass. A prediction that does not match the
			// action is worse than no prediction: it is the number an operator
			// decides on.
			if insertDecoded {
				already, err := s.hasDecodedPayload(row.id)
				if err != nil {
					return report, err
				}
				if already {
					insertDecoded = false
				}
			}
			if insertDecoded {
				report.DecodedRowsInserted++
			}
			continue
		}

		if err := s.applyReprocessedRow(row.id, res, insertDecoded, &report); err != nil {
			return report, err
		}
	}

	return report, nil
}

func (s *Store) collectReprocessRows() ([]reprocessRow, error) {
	// Read everything first, then write: holding a SELECT open across the
	// UPDATEs it drives is how a reprocessing pass ends up reading rows it
	// has already rewritten.
	rows, err := s.db.Query(`SELECT id, topic, payload, decode_status FROM raw_frames ORDER BY id;`)
	if err != nil {
		return nil, fmt.Errorf("storage: reading frames to reprocess: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []reprocessRow
	for rows.Next() {
		var r reprocessRow
		if err := rows.Scan(&r.id, &r.topic, &r.payload, &r.status); err != nil {
			return nil, fmt.Errorf("storage: scanning frame to reprocess: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterating frames to reprocess: %w", err)
	}
	return out, nil
}

// backupBeforeReprocess writes a consistent copy with VACUUM INTO, which is
// WAL-safe -- unlike copying the file, which leaves behind whatever is
// still in the -wal (docs/storage-schema.md §6).
func (s *Store) backupBeforeReprocess() (string, error) {
	var dbPath string
	if err := s.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name = 'main';`).Scan(&dbPath); err != nil {
		return "", fmt.Errorf("storage: locating the database file for the pre-reprocess backup: %w", err)
	}
	base := fmt.Sprintf("%s.pre-reprocess.%s", dbPath, time.Now().UTC().Format("20060102-150405"))
	// VACUUM INTO refuses to overwrite, which is the behaviour we want -- so
	// two passes inside the same second need distinct names rather than a
	// failed backup. Second-resolution timestamps are what an operator reads;
	// the suffix only appears when it has to.
	backup := base
	for attempt := 2; attempt <= 100; attempt++ {
		if _, err := os.Stat(backup); err != nil {
			break
		}
		backup = fmt.Sprintf("%s-%d", base, attempt)
	}
	if _, err := s.db.Exec(`VACUUM INTO ?;`, backup); err != nil {
		return "", fmt.Errorf("storage: backing up to %s before reprocessing: %w", backup, err)
	}
	return backup, nil
}

func (s *Store) frameWithinWindow(id int64, cutoff string) (bool, error) {
	var receivedAt string
	if err := s.db.QueryRow(`SELECT received_at FROM raw_frames WHERE id = ?;`, id).Scan(&receivedAt); err != nil {
		return false, fmt.Errorf("storage: reading received_at for frame %d: %w", id, err)
	}
	return receivedAt >= cutoff, nil
}

func (s *Store) applyReprocessedRow(id int64, res *decode.Result, insertDecoded bool, report *ReprocessReport) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("storage: beginning reprocess transaction: %w", err)
	}
	rollback := func(cause error) error {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("%w (additionally, rollback failed: %v)", cause, rbErr)
		}
		return cause
	}

	cols := reprocessedColumns(res)
	if _, err := tx.Exec(
		`UPDATE raw_frames SET
			decode_status = ?, decode_version = ?,
			rx_snr = ?, rx_rssi = ?, rx_time = ?, hop_limit = ?, hop_start = ?,
			want_ack = ?, via_mqtt = ?, priority = ?, relay_node = ?,
			portnum = ?, portnum_name = ?, want_response = ?,
			dest_node = ?, source_node = ?, request_id = ?, reply_id = ?, bitfield = ?
		 WHERE id = ?;`,
		append(cols, id)...,
	); err != nil {
		return rollback(fmt.Errorf("storage: updating reprocessed frame %d: %w", id, err))
	}

	if insertDecoded {
		// Idempotent: a second pass must not add a second decoded row for
		// the same frame.
		var existing int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM decoded_payloads WHERE raw_frame_id = ?;`, id).Scan(&existing); err != nil {
			return rollback(fmt.Errorf("storage: checking for an existing decoded payload for frame %d: %w", id, err))
		}
		if existing == 0 {
			hasFields, encoded, err := encodeDecodedFields(res)
			if err != nil {
				return rollback(err)
			}
			if hasFields {
				if _, err := tx.Exec(
					`INSERT INTO decoded_payloads (raw_frame_id, portnum, portnum_name, fields, decode_version)
					 VALUES (?, ?, ?, ?, ?);`,
					id, int64(res.Portnum), res.Portnum.Name(), encoded, DecodeVersion,
				); err != nil {
					return rollback(fmt.Errorf("storage: inserting reprocessed decoded payload for frame %d: %w", id, err))
				}
				report.DecodedRowsInserted++
			}
		}
	}

	// Node names are learnt from NODEINFO frames, which arrive a few times a
	// month. Reprocessing is the only way an existing database gets the ones
	// it received before this table existed, so it happens here too, inside
	// the same transaction as everything else about the frame.
	if res.Portnum == decode.PortNumNodeInfo {
		var receivedAt string
		if err := tx.QueryRow(`SELECT received_at FROM raw_frames WHERE id = ?;`, id).Scan(&receivedAt); err != nil {
			return rollback(fmt.Errorf("storage: reading received_at for frame %d: %w", id, err))
		}
		seenAt, err := time.Parse(time.RFC3339, receivedAt)
		if err != nil {
			return rollback(fmt.Errorf("storage: parsing received_at %q for frame %d: %w", receivedAt, id, err))
		}
		if err := recordNodeNameTx(tx, res, seenAt); err != nil {
			return rollback(err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: committing reprocessed frame %d: %w", id, err)
	}
	return nil
}

// hasDecodedPayload reports whether a frame already has a decoded row, so a
// dry run can predict insertions the way the apply path decides them.
func (s *Store) hasDecodedPayload(frameID int64) (bool, error) {
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM decoded_payloads WHERE raw_frame_id = ?;`, frameID,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("storage: checking for an existing decoded payload for frame %d: %w", frameID, err)
	}
	return n > 0, nil
}

// safeDecode wraps decode.Decode in a recover(), so one malformed stored
// payload cannot abort a pass over every other frame (ADR-2/ADR-3: a bug
// here must not take down the broker core).
func safeDecode(topic string, payload []byte, channels map[string][decode.PSKSize]byte) (res *decode.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("panic while decoding: %v", r)
		}
	}()
	return decode.Decode(topic, payload, channels)
}

// isDuplicateAmongEarlier answers the dedup question for a stored frame,
// looking only at frames stored before it -- the same information the live
// path had when that frame arrived. It shares IsDuplicate's identity rule:
// a frame with no gateway id or no packet id has no identity to compare, so
// it is never a duplicate.
func (s *Store) isDuplicateAmongEarlier(id int64, gatewayID string, packetID uint32) (bool, error) {
	if gatewayID == "" || packetID == 0 {
		return false, nil
	}

	var receivedAt string
	if err := s.db.QueryRow(`SELECT received_at FROM raw_frames WHERE id = ?;`, id).Scan(&receivedAt); err != nil {
		return false, fmt.Errorf("storage: reading received_at for frame %d: %w", id, err)
	}
	arrived, err := time.Parse(time.RFC3339, receivedAt)
	if err != nil {
		// An unparseable timestamp is not a reason to invent a duplicate.
		return false, nil
	}
	cutoff := arrived.Add(-DedupWindow).UTC().Format(time.RFC3339)

	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM raw_frames
		  WHERE gateway_id = ? AND packet_id = ? AND received_at >= ? AND id < ?;`,
		gatewayID, int64(packetID), cutoff, id,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("storage: reprocess dedup lookup for frame %d: %w", id, err)
	}
	return count > 0, nil
}
