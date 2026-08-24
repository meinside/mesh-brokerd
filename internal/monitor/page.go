package monitor

import (
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

//go:embed templates/page.html.tmpl
var templatesFS embed.FS

// pageTemplate is parsed once at startup, so a broken template is a startup
// failure rather than a 500 at the moment someone needs the page.
//
// html/template, not text/template: everything on this page comes from the
// mesh, and a message body is attacker-controlled text as far as this
// process is concerned.
var pageTemplate = template.Must(template.ParseFS(templatesFS, "templates/page.html.tmpl"))

// pageRefreshSeconds is how often the browser reloads. Traffic here is a few
// frames an hour, so this is about noticing a board dropping off, not about
// watching packets arrive.
const pageRefreshSeconds = 60

// recentFrameLimit and recentMessageLimit keep the page a page. A monitoring
// view that renders the whole database gets slower exactly as the thing it
// monitors gets busier.
const (
	recentFrameLimit   = 25
	recentMessageLimit = 15
	// maxPageLimit caps what ?frames= and ?messages= can ask for. A
	// monitoring view that renders the whole database gets slower exactly as
	// the thing it monitors gets busier, so the parameter widens the window
	// rather than removing it.
	maxPageLimit = 500
)

type pageData struct {
	// SinceStart labels every in-memory counter on this page: they all begin at
	// this process's start, and without it a small number looks like a lifetime
	// total rather than what happened since the last restart.
	SinceStart     string
	Hostname       string
	Now            string
	RefreshSeconds int

	Boards       []pageBoard
	Nodes        []pageNode
	Portnums     []pageCount
	RecentFrames []pageFrame
	Messages     []pageMessage

	// Totals and limits, so the page states that it is showing a window
	// rather than the record. A truncated list that does not say so is how a
	// reader concludes a message was never received.
	FrameLimit   int
	FrameTotal   int64
	MessageLimit int
	MessageTotal int64
	Health       pageHealth
	Outbound     []pageLabelled
	Telemetry    []pageTelemetry

	DisabledHookTargets string

	AuthVia   string
	AuthLogin string
}

type pageBoard struct {
	ID string
	// Status is derived from stored traffic; Session is the live MQTT
	// connection. They answer different questions, and a board can be
	// connected while quiet (nothing to say) or disconnected while its last
	// frame is recent (it just dropped).
	Status         string
	Session        string
	LastSeen       string
	Quiet          string
	Frames         int64
	DownlinkMissed int64
	Takeovers      int64
	NodeIDMismatch bool
}

type pageCount struct {
	Kind  string
	Count int64
}

type pageFrame struct {
	ReceivedAt string
	BoardID    string
	Portnum    string
	FromNode   string
	FromName   string
	SNR        float64
	HasSNR     bool
	Hops       int64
	HasHops    bool
	Status     string
}

type pageMessage struct {
	ReceivedAt string
	// StatedAt is the time the packet itself stated (raw_frames.rx_time),
	// empty when it stated none. It is shown beside ReceivedAt rather than
	// merged with it: one is our observation and the other is a claim by a
	// node whose clock we do not control, and a reader has to be able to tell
	// which is which (ADR-15).
	StatedAt string
	// Note explains a difference between the two times worth reading: a
	// message can sit in a gateway's queue for minutes -- one sat for 14m37s
	// across a brokerd restart -- and look instant if only its arrival is
	// shown.
	Note     string
	Channel  string
	FromNode string
	FromName string
	Text     string
}

// pageNode is one row of the node directory: a node id and what it currently
// calls itself.
//
// The table records more than this -- first sighting, how many NODEINFO frames
// taught the name, how many times it changed -- and keeps doing so, including a
// log line when a node renames itself. None of it is shown here: this page
// answers "what is the state now", and a history column is a different question
// that the database can be asked directly (docs/storage-schema.md §9).
type pageNode struct {
	NodeID    string
	LongName  string
	ShortName string
	LastSeen  string
}

type pageHealth struct {
	QueueDrops   int64
	AuthFailures int64
	ActiveBans   int
	Counters     []pageLabelled
}

type pageLabelled struct {
	Label string
	Value int64
	Warn  bool
}

type pageTelemetry struct {
	Source     string
	ReceivedAt string
	Summary    string
}

// handlePage renders the monitoring page (docs/monitoring-api.md §5).
//
// Every query below is read-only and bounded. A failing query degrades that
// section rather than the page: the reason to open this page is usually that
// something is already wrong, so it has to render while parts of the system
// are broken.
func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	auth := s.authenticate(r)

	host, err := os.Hostname()
	if err != nil {
		host = "unknown host"
	}

	data := pageData{
		Hostname:       host,
		Now:            time.Now().UTC().Format("2006-01-02 15:04:05 MST"),
		RefreshSeconds: pageRefreshSeconds,
		AuthVia:        auth.via,
		AuthLogin:      auth.login,
		SinceStart:     humanDuration(time.Since(s.startedAt)),
	}

	data.FrameLimit = clampLimit(r.URL.Query().Get("frames"), recentFrameLimit)
	data.MessageLimit = clampLimit(r.URL.Query().Get("messages"), recentMessageLimit)

	// Read the names once and hand them to both lists: one map lookup per row
	// beats a query per row, and it keeps every row on the page consistent
	// with the others even if a NODEINFO frame arrives mid-render.
	names := s.store.NodeNames()

	data.Boards = s.pageBoards()
	data.Nodes = nodeDirectory(names)
	data.Portnums = s.pagePortnums()
	data.RecentFrames = s.pageRecentFrames(data.FrameLimit, names)
	data.Messages = s.pageMessages(data.MessageLimit, names)
	data.FrameTotal = s.countRows(`SELECT COUNT(*) FROM raw_frames;`)
	data.MessageTotal = s.countRows(
		`SELECT COUNT(*) FROM text_messages t JOIN raw_frames r ON r.id = t.raw_frame_id
		  WHERE r.decode_status <> 'duplicate';`)
	data.Health = s.pageHealth()
	data.Outbound = s.pageOutbound()
	data.Telemetry = s.pageTelemetry()

	if s.hooks != nil {
		if disabled := s.hooks.Snapshot().Disabled; len(disabled) > 0 {
			data.DisabledHookTargets = strings.Join(disabled, ", ")
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page contains message text; a cache is one more copy of it.
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplate.Execute(w, data); err != nil {
		// Too late for a status code -- the template has already written
		// part of the body. Nothing to do but stop.
		return
	}
}

func (s *Server) pageBoards() []pageBoard {
	connected := map[string]bool{}
	var missed map[string]int64
	var takeovers map[string]int64
	var mismatches map[string]int64
	// Without a broker there is no session information at all. Saying
	// "absent" would state a fact this process does not have.
	sessionKnown := s.broker != nil
	if s.broker != nil {
		for _, id := range s.broker.ConnectedBoards() {
			connected[id] = true
		}
		missed = s.broker.DownlinkMissed()
		takeovers = s.broker.SessionTakeovers()
		mismatches = s.broker.NodeIDMismatches()
	}

	lastSeen, frames := s.boardActivity()

	out := make([]pageBoard, 0, len(s.boards))
	for _, b := range s.boards {
		row := pageBoard{
			ID:             b.ID,
			Status:         "silent",
			Session:        "unknown",
			Frames:         frames[b.ID],
			DownlinkMissed: missed[b.ID],
			Takeovers:      takeovers[b.ID],
		}
		if sessionKnown {
			row.Session = "absent"
			if connected[b.ID] {
				row.Session = "connected"
			}
		}
		if t, ok := lastSeen[b.ID]; ok {
			row.LastSeen = t.UTC().Format("2006-01-02 15:04:05")
			row.Quiet = time.Since(t).Round(time.Minute).String()
			if time.Since(t) <= onlineWithin {
				row.Status = "online"
			}
		}
		for value := range mismatches {
			// The checker keys its counter on the observed gateway_id, not
			// on the board, so a non-empty map is reported against every
			// board rather than guessed at.
			_ = value
			row.NodeIDMismatch = true
			break
		}
		out = append(out, row)
	}
	return out
}

func (s *Server) boardActivity() (map[string]time.Time, map[string]int64) {
	lastSeen := map[string]time.Time{}
	frames := map[string]int64{}

	rows, err := s.store.DB().Query(
		`SELECT board_id, MAX(received_at), COUNT(*) FROM raw_frames GROUP BY board_id;`)
	if err != nil {
		return lastSeen, frames
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var board, last string
		var count int64
		if err := rows.Scan(&board, &last, &count); err != nil {
			continue
		}
		frames[board] = count
		if t, err := time.Parse(time.RFC3339, last); err == nil {
			lastSeen[board] = t
		}
	}
	return lastSeen, frames
}

func (s *Server) pagePortnums() []pageCount {
	rows, err := s.store.DB().Query(
		`SELECT COALESCE(portnum_name, '(not decoded)'), COUNT(*)
		   FROM raw_frames GROUP BY 1 ORDER BY 2 DESC;`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []pageCount
	for rows.Next() {
		var c pageCount
		if err := rows.Scan(&c.Kind, &c.Count); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (s *Server) pageRecentFrames(limit int, names map[uint32]storage.NodeName) []pageFrame {
	rows, err := s.store.DB().Query(
		`SELECT received_at, board_id, COALESCE(portnum_name, ''),
		        from_node, rx_snr, hop_start, decode_status
		   FROM raw_frames ORDER BY id DESC LIMIT ?;`, limit)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []pageFrame
	for rows.Next() {
		var (
			receivedAt string
			f          pageFrame
			fromNode   sql.NullInt64
			snr        sql.NullFloat64
			hops       sql.NullInt64
		)
		if err := rows.Scan(&receivedAt, &f.BoardID, &f.Portnum, &fromNode, &snr, &hops, &f.Status); err != nil {
			continue
		}
		f.ReceivedAt = shortTime(receivedAt)
		f.FromNode = nodeIDString(fromNode)
		f.FromName = nodeDisplayName(names, fromNode)
		f.SNR, f.HasSNR = snr.Float64, snr.Valid
		f.Hops, f.HasHops = hops.Int64, hops.Valid
		out = append(out, f)
	}
	return out
}

func (s *Server) pageMessages(limit int, names map[uint32]storage.NodeName) []pageMessage {
	// Both times come from raw_frames: received_at is when brokerd got the
	// frame, rx_time is the time the packet stated. text_messages carries a copy
	// of received_at under the same name; it has never held a time a node
	// stated, whatever an earlier version of this comment claimed.
	//
	// Frames marked duplicate are excluded here rather than deleted
	// anywhere: storage keeps every delivery on purpose (ADR-3/ADR-14), but
	// a re-delivery is not new content, and rows written before duplicate
	// suppression existed would otherwise show one message three times.
	// Two identical messages sent deliberately have different packet ids,
	// are not duplicates, and still both appear.
	rows, err := s.store.DB().Query(
		`SELECT r.received_at, r.rx_time, COALESCE(t.channel_name, ''), t.from_node, t.text
		   FROM text_messages t JOIN raw_frames r ON r.id = t.raw_frame_id
		  WHERE r.decode_status <> 'duplicate'
		  ORDER BY t.id DESC LIMIT ?;`, limit)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []pageMessage
	for rows.Next() {
		var (
			receivedAt string
			rxTime     sql.NullInt64
			m          pageMessage
			fromNode   sql.NullInt64
		)
		if err := rows.Scan(&receivedAt, &rxTime, &m.Channel, &fromNode, &m.Text); err != nil {
			continue
		}
		m.ReceivedAt = shortTime(receivedAt)
		m.StatedAt, m.Note = statedTimeAndNote(receivedAt, rxTime)
		m.FromNode = nodeIDString(fromNode)
		m.FromName = nodeDisplayName(names, fromNode)
		out = append(out, m)
	}
	return out
}

func (s *Server) pageHealth() pageHealth {
	h := pageHealth{}
	if s.broker != nil {
		h.QueueDrops = s.broker.DropCount()
		h.Counters = append(h.Counters, labelledCounts("decode failures", s.broker.DecodeStatusCounts(), "decoded")...)
		h.Counters = append(h.Counters, labelledCounts("listener noise suppressed", s.broker.ListenerNoiseCounts())...)
		h.Counters = append(h.Counters, labelledCounts("ACL refusals", s.broker.ACLDenials())...)
		h.Counters = append(h.Counters, labelledCounts("board node_id mismatch", s.broker.NodeIDMismatches())...)
	}
	if s.authHook != nil {
		h.AuthFailures = s.authHook.FailuresTotal()
		h.ActiveBans = len(s.authHook.ActiveBans())
	}
	return h
}

// pageOutbound lists what the relay and the hooks are configured to do and what
// they have done.
//
// Both halves are needed. Showing only counters made a configured relay with
// nothing published yet render as "not configured" -- and the relay publishes
// once an hour, so that was the normal state right after a restart. A zero is a
// measurement; an empty section is a claim about the configuration, and it was
// the wrong one (the same absent-vs-zero rule as ADR-15).
func (s *Server) pageOutbound() []pageLabelled {
	var out []pageLabelled

	if s.broker != nil {
		dryRun, published, failures := s.broker.OutboundRelayCounters()
		for _, rule := range s.broker.OutboundRelayRules() {
			label := "relay " + rule.ID
			switch {
			case !rule.Enabled:
				label += " (disabled)"
			case rule.DryRun:
				label += " (dry run)"
			}
			out = append(out, pageLabelled{Label: label + " published", Value: published[rule.ID]})
			if n := dryRun[rule.ID]; n > 0 {
				out = append(out, pageLabelled{Label: label + " dry run", Value: n})
			}
			if n := failures[rule.ID]; n > 0 {
				out = append(out, pageLabelled{Label: label + " failures", Value: n, Warn: true})
			}
		}
	}

	if s.hooks != nil {
		snap := s.hooks.Snapshot()
		for _, t := range s.hooks.ConfiguredTargets() {
			label := "hook " + t.Name
			if !t.Enabled {
				label += " (disabled)"
			}
			out = append(out, pageLabelled{Label: label + " fired", Value: snap.Fired[t.Name]})
			for _, extra := range []struct {
				name string
				n    int64
				warn bool
			}{
				{"failed", snap.Failed[t.Name], true},
				{"dropped", snap.Dropped[t.Name], true},
				{"rate limited", snap.RateLimited[t.Name], false},
				{"suppressed", snap.Suppressed[t.Name], false},
				{"dry run", snap.DryRun[t.Name], false},
			} {
				if extra.n > 0 {
					out = append(out, pageLabelled{Label: label + " " + extra.name, Value: extra.n, Warn: extra.warn})
				}
			}
		}
	}

	return out
}

// pageTelemetry reads the most recent device metrics per source. Empty until
// TELEMETRY_APP traffic actually arrives, which the page says in words
// rather than by showing an empty table.
func (s *Server) pageTelemetry() []pageTelemetry {
	rows, err := s.store.DB().Query(
		`SELECT r.board_id, r.received_at, d.fields
		   FROM decoded_payloads d JOIN raw_frames r ON r.id = d.raw_frame_id
		  WHERE d.portnum_name = 'TELEMETRY_APP'
		  ORDER BY d.id DESC LIMIT 10;`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()

	seen := map[string]bool{}
	var out []pageTelemetry
	for rows.Next() {
		var source, receivedAt, fields string
		if err := rows.Scan(&source, &receivedAt, &fields); err != nil {
			continue
		}
		if seen[source] {
			continue
		}
		seen[source] = true
		out = append(out, pageTelemetry{
			Source:     source,
			ReceivedAt: shortTime(receivedAt),
			Summary:    fields,
		})
	}
	return out
}

// labelledCounts turns a counter map into stable, sorted rows. skip names a
// key that is not a problem and would only pad the table.
func labelledCounts(prefix string, counts map[string]int64, skip ...string) []pageLabelled {
	skipped := map[string]bool{}
	for _, s := range skip {
		skipped[s] = true
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		if !skipped[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	out := make([]pageLabelled, 0, len(keys))
	for _, k := range keys {
		out = append(out, pageLabelled{
			Label: fmt.Sprintf("%s: %s", prefix, k),
			Value: counts[k],
			Warn:  counts[k] > 0,
		})
	}
	return out
}

// shortTime trims an RFC 3339 timestamp to what fits on a phone screen,
// leaving it in UTC -- the timezone the database uses, so a value on the
// page can be pasted into a query.
func shortTime(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	return t.UTC().Format("01-02 15:04:05")
}

func nodeIDString(v sql.NullInt64) string {
	if !v.Valid {
		return "—"
	}
	return fmt.Sprintf("!%08x", uint32(v.Int64))
}

// clampLimit reads a row limit from the query string. An unparseable or
// out-of-range value is clamped rather than rejected: a monitoring page
// answering 400 to a mistyped URL would be the least useful possible
// response.
func clampLimit(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	if n > maxPageLimit {
		return maxPageLimit
	}
	return n
}

// countRows runs a COUNT query, returning 0 if it fails: a failing count
// degrades one number on the page rather than the page.
func (s *Server) countRows(query string) int64 {
	var n int64
	if err := s.store.DB().QueryRow(query).Scan(&n); err != nil {
		return 0
	}
	return n
}

// FrameTotal64 and MessageTotal64 exist because html/template cannot compare
// an int (len) with an int64 (a COUNT) using `lt`.
func (d pageData) FrameTotal64() int { return int(d.FrameTotal) }

func (d pageData) MessageTotal64() int { return int(d.MessageTotal) }

// NextFrameLimit and NextMessageLimit suggest a wider window without
// inventing paging: one link that shows more, capped by maxPageLimit.
func (d pageData) NextFrameLimit() int { return nextLimit(d.FrameLimit) }

func (d pageData) NextMessageLimit() int { return nextLimit(d.MessageLimit) }

func nextLimit(current int) int {
	next := current * 4
	if next > maxPageLimit {
		return maxPageLimit
	}
	return next
}

// nodeDisplayName is the name to show beside a node id, or "" when none has
// been learnt: the long name with the short name after it, the same string a
// hook payload carries as from_name (decode.FormatNodeName).
//
// It never falls back to the id. The id has its own column, and repeating it
// here would make a node that has never introduced itself look named -- the
// dash says which of the two it is (ADR-15).
func nodeDisplayName(names map[uint32]storage.NodeName, v sql.NullInt64) string {
	if !v.Valid || names == nil {
		return ""
	}
	return names[uint32(v.Int64)].Display()
}

// nodeDirectory lists every node that has ever introduced itself, newest
// sighting first. It reads the node_names table, which retention does not
// touch, so a node that has been quiet for months is still named here.
func nodeDirectory(names map[uint32]storage.NodeName) []pageNode {
	out := make([]pageNode, 0, len(names))
	for _, n := range names {
		// A row with no usable name is not a directory entry. Storage refuses
		// to record one, but a row written by hand or by an older build would
		// otherwise render as two dashes and an id, which says less than
		// leaving the node to the Name column of the lists above.
		if n.Display() == "" {
			continue
		}
		out = append(out, pageNode{
			NodeID:    decode.NodeIDString(n.NodeID),
			LongName:  n.LongName,
			ShortName: n.ShortName,
			LastSeen:  n.LastSeen.UTC().Format("2006-01-02 15:04"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out
}

// clockNoteThreshold is how far the packet's stated time may sit from arrival
// before it is worth a note. Below it the difference is transit and rounding,
// which is every normal message.
const clockNoteThreshold = time.Minute

// statedTimeAndNote renders the packet's own timestamp and, when it disagrees
// with arrival by more than clockNoteThreshold, what the disagreement means.
//
// Two directions, two meanings. Stated *earlier* than arrival is a delay: the
// frame waited somewhere, typically in a gateway's queue while it had no MQTT
// connection. Stated *later* is not possible physically, so it says the node's
// clock is ahead -- worth showing as such rather than as a negative delay,
// because the reader's next question is which of the two clocks to trust.
//
// An unstated rx_time returns "", "": the caller renders that as a dash. Filling
// it in with arrival would make our own observation look like the node's claim
// (ADR-15).
func statedTimeAndNote(receivedAt string, rxTime sql.NullInt64) (stated, note string) {
	if !rxTime.Valid || rxTime.Int64 <= 0 {
		return "", ""
	}
	statedTime := time.Unix(rxTime.Int64, 0).UTC()
	stated = shortTime(statedTime.Format(time.RFC3339))

	arrived, err := time.Parse(time.RFC3339, receivedAt)
	if err != nil {
		return stated, ""
	}
	switch d := arrived.Sub(statedTime); {
	case d >= clockNoteThreshold:
		return stated, "queued " + d.Round(time.Second).String()
	case -d >= clockNoteThreshold:
		return stated, "node clock ahead " + (-d).Round(time.Second).String()
	default:
		return stated, ""
	}
}

// humanDuration renders an uptime the way the page's other durations read:
// coarse on purpose, since "since start" only has to tell a reader whether a
// counter covers minutes or weeks.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}
