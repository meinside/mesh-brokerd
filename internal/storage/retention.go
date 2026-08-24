package storage

import (
	"fmt"
	"time"
)

// DeleteExpired runs the two independent retention deletions
// (docs/storage-schema.md §6, ADR-7). A days value of 0 means
// unlimited — that table is skipped entirely, never deleted from.
// Returns the number of rows deleted from each table; decodedDeleted
// covers both decoded tables (text_messages and decoded_payloads).
//
// decoded_payloads has no timestamp of its own — a decoded payload's time
// is its raw frame's arrival time — so it is pruned through that join, and
// then any row whose raw frame is already gone is swept regardless of the
// configured decoded retention: a shorter raw_frames retention must not
// leave rows pointing at frames that no longer exist.
func (s *Store) DeleteExpired(rawFramesDays, decodedDays int) (rawDeleted, decodedDeleted int64, err error) {
	if rawFramesDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -rawFramesDays).Format(time.RFC3339)
		res, err := s.db.Exec(`DELETE FROM raw_frames WHERE received_at < ?;`, cutoff)
		if err != nil {
			return 0, 0, fmt.Errorf("storage: deleting expired raw_frames: %w", err)
		}
		rawDeleted, _ = res.RowsAffected()
	}

	if decodedDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -decodedDays).Format(time.RFC3339)
		res, err := s.db.Exec(`DELETE FROM text_messages WHERE received_at < ?;`, cutoff)
		if err != nil {
			return rawDeleted, 0, fmt.Errorf("storage: deleting expired text_messages: %w", err)
		}
		decodedDeleted, _ = res.RowsAffected()

		res, err = s.db.Exec(
			`DELETE FROM decoded_payloads
			  WHERE raw_frame_id IN (SELECT id FROM raw_frames WHERE received_at < ?);`, cutoff)
		if err != nil {
			return rawDeleted, decodedDeleted, fmt.Errorf("storage: deleting expired decoded_payloads: %w", err)
		}
		n, _ := res.RowsAffected()
		decodedDeleted += n
	}

	res, err := s.db.Exec(
		`DELETE FROM decoded_payloads
		  WHERE NOT EXISTS (SELECT 1 FROM raw_frames r WHERE r.id = decoded_payloads.raw_frame_id);`)
	if err != nil {
		return rawDeleted, decodedDeleted, fmt.Errorf("storage: sweeping orphaned decoded_payloads: %w", err)
	}
	n, _ := res.RowsAffected()
	decodedDeleted += n

	return rawDeleted, decodedDeleted, nil
}
