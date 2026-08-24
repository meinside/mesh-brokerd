package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// NodeName is what a node has said about itself. Every string may be empty:
// a NODEINFO frame states what it states, and an empty long name is "not
// stated", not "no name" (ADR-15).
type NodeName struct {
	NodeID    uint32
	LongName  string
	ShortName string
	HWModel   int64
	Role      int64
	StatedID  string
	FirstSeen time.Time
	LastSeen  time.Time
	Updates   int64
	Renames   int64
}

// Display is the name to show for a node, or "" when nothing is known: the long
// name with the short name after it. A node that set only one of them is still
// recognisable, and a node that set neither has no name (ADR-15).
func (n NodeName) Display() string {
	return decode.FormatNodeName(n.LongName, n.ShortName)
}

// nameCache holds node_names in memory. It is read on every rendered page row
// and on every dispatched hook event, and written a few times a month, so the
// read path must not be a query per node id.
type nameCache struct {
	mu sync.RWMutex
	by map[uint32]NodeName
}

func (c *nameCache) get(id uint32) (NodeName, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n, ok := c.by[id]
	return n, ok
}

func (c *nameCache) put(n NodeName) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.by == nil {
		c.by = make(map[uint32]NodeName)
	}
	c.by[n.NodeID] = n
}

func (c *nameCache) snapshot() map[uint32]NodeName {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[uint32]NodeName, len(c.by))
	for k, v := range c.by {
		out[k] = v
	}
	return out
}

// loadNodeNames fills the cache from the table. Called once on Open.
func (s *Store) loadNodeNames() error {
	rows, err := s.db.Query(`SELECT node_id, COALESCE(long_name,''), COALESCE(short_name,''),
	                                COALESCE(hw_model,-1), COALESCE(role,-1), COALESCE(stated_id,''),
	                                first_seen, last_seen, updates, renames
	                           FROM node_names;`)
	if err != nil {
		return fmt.Errorf("loading node_names: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			n                   NodeName
			id                  int64
			firstSeen, lastSeen string
		)
		if err := rows.Scan(&id, &n.LongName, &n.ShortName, &n.HWModel, &n.Role,
			&n.StatedID, &firstSeen, &lastSeen, &n.Updates, &n.Renames); err != nil {
			return fmt.Errorf("scanning node_names: %w", err)
		}
		n.NodeID = uint32(id)
		// Rows written before names were normalised, or by hand, are cleaned
		// on the way in so the cache matches what a fresh write would store.
		n.LongName, n.ShortName = normalizeName(n.LongName), normalizeName(n.ShortName)
		n.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		n.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		s.names.put(n)
	}
	return rows.Err()
}

// LookupNodeName returns what is known about a node id.
func (s *Store) LookupNodeName(id uint32) (NodeName, bool) { return s.names.get(id) }

// NodeNames returns a copy of everything known, for rendering.
func (s *Store) NodeNames() map[uint32]NodeName { return s.names.snapshot() }

// RecordNodeName stores what a NODEINFO frame said about its sender. It is a
// no-op for any other portnum, so both the live write path and reprocessing
// can call it with whatever they just decoded.
//
// Returns whether the long name differed from what was already known, which is
// worth a log line: a node's name changing is the kind of thing that makes a
// stored history confusing later.
func (s *Store) RecordNodeName(res *decode.Result, seenAt time.Time) (renamed bool, err error) {
	if res == nil || res.Portnum != decode.PortNumNodeInfo || res.NodeInfo == nil {
		return false, nil
	}
	ni := res.NodeInfo
	long, short := normalizeName(ni.LongName), normalizeName(ni.ShortName)
	if long == "" && short == "" {
		return false, nil // states no name; nothing to record
	}

	// The payload also spells out whose it is. Every real frame observed so
	// far agrees with the packet's from field, but a disagreement would mean
	// the name belongs to a different node than the one that sent it, so
	// record what was stated rather than assuming.
	statedID := ni.ID
	nodeID := res.FromNode

	prev, had := s.names.get(nodeID)
	renamed = had && prev.LongName != "" && long != "" && prev.LongName != long

	// A field the frame did not state must not erase what is known (ADR-15).
	// Protobuf omits an empty string, so "" here means "said nothing about it",
	// not "cleared it" -- and a node that broadcasts only its short name would
	// otherwise wipe the long name everything displays.
	keptLong, keptShort := long, short
	if keptLong == "" {
		keptLong = prev.LongName
	}
	if keptShort == "" {
		keptShort = prev.ShortName
	}

	next := NodeName{
		NodeID: nodeID, LongName: keptLong, ShortName: keptShort,
		StatedID: statedID, LastSeen: seenAt.UTC(),
		Updates: prev.Updates + 1, Renames: prev.Renames,
		HWModel: -1, Role: -1,
	}
	if ni.HasHWModel {
		next.HWModel = int64(ni.HWModel)
	}
	if ni.HasRole {
		next.Role = int64(ni.Role)
	}
	if renamed {
		next.Renames++
	}
	next.FirstSeen = seenAt.UTC()
	if had && !prev.FirstSeen.IsZero() {
		next.FirstSeen = prev.FirstSeen
	}

	if err := upsertNodeNameRow(s.db, next, ni); err != nil {
		return false, err
	}
	s.names.put(next)
	return renamed, nil
}

// execer is satisfied by both *sql.DB and *sql.Tx, so the live write path and
// reprocessing (which needs the write inside its own transaction) share one
// statement instead of two that can drift.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func upsertNodeNameRow(db execer, next NodeName, ni *decode.NodeInfo) error {
	_, err := db.Exec(
		`INSERT INTO node_names
		   (node_id, long_name, short_name, hw_model, role, stated_id, first_seen, last_seen, updates, renames)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET
		   long_name = COALESCE(excluded.long_name, node_names.long_name),
		   short_name = COALESCE(excluded.short_name, node_names.short_name),
		   hw_model = COALESCE(excluded.hw_model, node_names.hw_model),
		   role = COALESCE(excluded.role, node_names.role),
		   stated_id = excluded.stated_id,
		   last_seen = excluded.last_seen,
		   updates = node_names.updates + 1,
		   renames = excluded.renames;`,
		int64(next.NodeID), nullIfEmpty(next.LongName), nullIfEmpty(next.ShortName),
		nullIfNegative(next.HWModel), nullIfNegative(next.Role), nullIfEmpty(next.StatedID),
		next.FirstSeen.Format(time.RFC3339), next.LastSeen.Format(time.RFC3339),
		next.Updates, next.Renames)
	if err != nil {
		return fmt.Errorf("recording node name: %w", err)
	}
	return nil
}

// normalizeName is the single place a stated name is cleaned up, so the
// database, the in-memory cache, the page and a hook payload cannot disagree
// about whether a node has a name.
//
// A name is arbitrary text typed by whoever owns the radio, and several things
// it can contain are not names to a reader:
//
//   - " " and "\n" render as a blank cell, which looks like a bug rather than
//     like "this node has no name";
//   - control characters (Cc) would go into an HTML table and a chat message;
//   - format characters (Cf) such as U+200B ZERO WIDTH SPACE are invisible, so
//     a name made only of them is empty to everyone looking at it while being
//     a non-empty Go string.
//
// Anything printable is kept, emoji included: those are real names.
func normalizeName(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		if !unicode.IsGraphic(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(cleaned)
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nullIfNegative(v int64) any {
	if v < 0 {
		return nil
	}
	return v
}

// recordNodeNameTx is RecordNodeName for a caller that already has a
// transaction open. It does not touch the in-memory cache: reprocessing runs
// as its own process against a database no server is serving from, and a
// running server reloads names on Open.
func recordNodeNameTx(tx *sql.Tx, res *decode.Result, seenAt time.Time) error {
	if res == nil || res.Portnum != decode.PortNumNodeInfo || res.NodeInfo == nil {
		return nil
	}
	ni := res.NodeInfo
	long, short := normalizeName(ni.LongName), normalizeName(ni.ShortName)
	if long == "" && short == "" {
		return nil
	}

	next := NodeName{
		NodeID: res.FromNode, LongName: long, ShortName: short,
		StatedID: ni.ID, FirstSeen: seenAt.UTC(), LastSeen: seenAt.UTC(),
		Updates: 1, HWModel: -1, Role: -1,
	}
	if ni.HasHWModel {
		next.HWModel = int64(ni.HWModel)
	}
	if ni.HasRole {
		next.Role = int64(ni.Role)
	}

	// Reprocessing walks frames oldest-first, so keep the earliest first_seen
	// and the latest name: MIN/MAX in SQL rather than a read-modify-write, so
	// the order rows arrive in cannot change the result.
	_, err := tx.Exec(
		`INSERT INTO node_names
		   (node_id, long_name, short_name, hw_model, role, stated_id, first_seen, last_seen, updates, renames)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
		 ON CONFLICT(node_id) DO UPDATE SET
		   long_name  = CASE WHEN excluded.last_seen >= node_names.last_seen
		                     THEN COALESCE(excluded.long_name, node_names.long_name)
		                     ELSE node_names.long_name END,
		   short_name = CASE WHEN excluded.last_seen >= node_names.last_seen
		                     THEN COALESCE(excluded.short_name, node_names.short_name)
		                     ELSE node_names.short_name END,
		   hw_model   = COALESCE(excluded.hw_model, node_names.hw_model),
		   role       = COALESCE(excluded.role, node_names.role),
		   stated_id  = COALESCE(excluded.stated_id, node_names.stated_id),
		   first_seen = MIN(node_names.first_seen, excluded.first_seen),
		   last_seen  = MAX(node_names.last_seen, excluded.last_seen),
		   updates    = node_names.updates + 1,
		   renames    = node_names.renames + CASE
		                  WHEN excluded.long_name IS NOT NULL
		                   AND node_names.long_name IS NOT NULL
		                   AND excluded.long_name <> node_names.long_name
		                   AND excluded.last_seen >= node_names.last_seen
		                  THEN 1 ELSE 0 END;`,
		int64(next.NodeID), nullIfEmpty(next.LongName), nullIfEmpty(next.ShortName),
		nullIfNegative(next.HWModel), nullIfNegative(next.Role), nullIfEmpty(ni.ID),
		next.FirstSeen.Format(time.RFC3339), next.LastSeen.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("recording node name during reprocessing: %w", err)
	}
	return nil
}

// NodeNameFor implements hook.NameResolver without internal/storage having to
// import internal/hook.
func (s *Store) NodeNameFor(id uint32) (long, short string, ok bool) {
	n, found := s.names.get(id)
	if !found || (n.LongName == "" && n.ShortName == "") {
		return "", "", false
	}
	return n.LongName, n.ShortName, true
}
