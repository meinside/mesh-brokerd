package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

func nodeInfoResult(from uint32, long, short string) *decode.Result {
	return &decode.Result{
		PacketParsed: true,
		Portnum:      decode.PortNumNodeInfo,
		FromNode:     from,
		NodeInfo: &decode.NodeInfo{
			ID: decode.NodeIDString(from), LongName: long, ShortName: short,
			HWModel: 110, HasHWModel: true,
		},
	}
}

// TestRecordNodeName_SurvivesRetention is the reason node_names is a table and
// not a query over decoded_payloads: NODEINFO arrives a handful of times a
// month, so once retention passes over the frame that carried it, a derived
// lookup would have no name left to find.
func TestRecordNodeName_SurvivesRetention(t *testing.T) {
	s := openTestStore(t)

	long := time.Now().UTC().AddDate(0, 0, -400) // far outside any window
	if _, err := s.RecordNodeName(nodeInfoResult(0x11223344, "Alpha Node", "ALFA"), long); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}

	if _, _, err := s.DeleteExpired(1, 1); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	got, ok := s.LookupNodeName(0x11223344)
	if !ok {
		t.Fatal("node name deleted by retention; the name outliving its frame is the point of the table")
	}
	if got.LongName != "Alpha Node" {
		t.Errorf("LongName = %q", got.LongName)
	}
}

// TestRecordNodeName_PersistsAcrossReopen: the in-memory cache is a cache, and
// a restart must not lose what the database was told.
func TestRecordNodeName_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.RecordNodeName(nodeInfoResult(0x55667788, "Bravo Node", "BRVO"), time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	long, short, ok := reopened.NodeNameFor(0x55667788)
	if !ok || long != "Bravo Node" || short != "BRVO" {
		t.Errorf("after reopen: long=%q short=%q ok=%v", long, short, ok)
	}
}

// TestRecordNodeName_TracksARename covers something real traffic did: a node
// changed its long name mid-month. The current name has to win, the first
// sighting has to survive, and the change has to be visible rather than
// silently overwriting history.
func TestRecordNodeName_TracksARename(t *testing.T) {
	s := openTestStore(t)

	first := time.Now().UTC().Add(-48 * time.Hour)
	if renamed, err := s.RecordNodeName(nodeInfoResult(0x99aabbcc, "Old Name", "OLD"), first); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	} else if renamed {
		t.Error("first sighting reported as a rename")
	}

	later := time.Now().UTC()
	renamed, err := s.RecordNodeName(nodeInfoResult(0x99aabbcc, "New Name", "NEW"), later)
	if err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}
	if !renamed {
		t.Error("a changed long name was not reported as a rename")
	}

	got, _ := s.LookupNodeName(0x99aabbcc)
	if got.LongName != "New Name" {
		t.Errorf("LongName = %q, want the current one", got.LongName)
	}
	if !got.FirstSeen.Equal(first.Truncate(time.Second)) && got.FirstSeen.After(first.Add(time.Second)) {
		t.Errorf("FirstSeen = %v, want the first sighting %v", got.FirstSeen, first)
	}
	if got.Updates != 2 {
		t.Errorf("Updates = %d, want 2", got.Updates)
	}
	if got.Renames != 1 {
		t.Errorf("Renames = %d, want 1", got.Renames)
	}

	// Re-sending the same name is not a rename.
	if renamed, err := s.RecordNodeName(nodeInfoResult(0x99aabbcc, "New Name", "NEW"), later.Add(time.Hour)); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	} else if renamed {
		t.Error("an unchanged name reported as a rename")
	}
}

// TestNodeNameFor_UnknownNodeStatesNothing: an unnamed node must not be given
// its own id as a name. The page and the hook payload both distinguish "no
// name learnt" from a name, and they can only do that if this does.
func TestNodeNameFor_UnknownNodeStatesNothing(t *testing.T) {
	s := openTestStore(t)

	if long, short, ok := s.NodeNameFor(0x11223344); ok || long != "" || short != "" {
		t.Errorf("unknown node returned long=%q short=%q ok=%v", long, short, ok)
	}
	// A NODEINFO frame stating no name at all is not a name either.
	if _, err := s.RecordNodeName(nodeInfoResult(0x11223344, "", ""), time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}
	if _, _, ok := s.NodeNameFor(0x11223344); ok {
		t.Error("a NODEINFO frame with no name recorded a name")
	}
}

// TestRecordNodeName_IgnoresOtherPortnums keeps the write path honest: only a
// NODEINFO frame says what a node is called.
func TestRecordNodeName_IgnoresOtherPortnums(t *testing.T) {
	s := openTestStore(t)

	res := &decode.Result{PacketParsed: true, Portnum: decode.PortNumTextMessage, FromNode: 0x11223344}
	if renamed, err := s.RecordNodeName(res, time.Now()); err != nil || renamed {
		t.Fatalf("RecordNodeName on a text frame: renamed=%v err=%v", renamed, err)
	}
	if len(s.NodeNames()) != 0 {
		t.Errorf("NodeNames = %v, want empty", s.NodeNames())
	}
}

// TestRecordNodeName_WhitespaceOnlyNameIsNoName: a name is arbitrary text typed
// by whoever owns the radio, and " " or "\n" is a name a node really can
// broadcast. Storing it produces a blank cell on the page and a label like
// " (!11223344)", which reads as a bug rather than as "this node has no name".
func TestRecordNodeName_WhitespaceOnlyNameIsNoName(t *testing.T) {
	s := openTestStore(t)

	for _, name := range []string{" ", "\t", "\n\n", "  \t \n", "\u0000", "\u200b\u200b"} {
		if _, err := s.RecordNodeName(nodeInfoResult(0x11223344, name, name), time.Now()); err != nil {
			t.Fatalf("RecordNodeName(%q): %v", name, err)
		}
		if long, short, ok := s.NodeNameFor(0x11223344); ok {
			t.Errorf("name %q was recorded as a name: long=%q short=%q", name, long, short)
		}
	}
}

// TestRecordNodeName_CacheAndDatabaseAgree pins the class of bug where a value
// is cleaned on its way into the database but not into the in-memory cache: the
// page would show one thing before a restart and another after it, and only the
// restart would reveal which was intended.
func TestRecordNodeName_CacheAndDatabaseAgree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agree.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Names with surrounding whitespace and an embedded control character.
	if _, err := s.RecordNodeName(nodeInfoResult(0x11223344, "  Alpha\u0000 Node  ", " ALFA "), time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}
	inMemory, _ := s.LookupNodeName(0x11223344)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	fromDB, _ := reopened.LookupNodeName(0x11223344)

	if inMemory.LongName != fromDB.LongName || inMemory.ShortName != fromDB.ShortName {
		t.Errorf("cache and database disagree:\n  cache: long=%q short=%q\n  db:    long=%q short=%q",
			inMemory.LongName, inMemory.ShortName, fromDB.LongName, fromDB.ShortName)
	}
	if fromDB.LongName != "Alpha Node" {
		t.Errorf("LongName = %q, want the trimmed name with the control character removed", fromDB.LongName)
	}
	if fromDB.ShortName != "ALFA" {
		t.Errorf("ShortName = %q", fromDB.ShortName)
	}
}

// TestRecordNodeName_UnstatedFieldDoesNotEraseAKnownOne: protobuf omits an empty
// string, so a NODEINFO frame carrying only a short name says nothing about the
// long one. Treating that as "cleared" would wipe the name every surface
// displays (ADR-15).
func TestRecordNodeName_UnstatedFieldDoesNotEraseAKnownOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keep.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := s.RecordNodeName(nodeInfoResult(0x11223344, "Alpha Node", "ALFA"), time.Now()); err != nil {
		t.Fatalf("first RecordNodeName: %v", err)
	}
	// A later frame states only the short name.
	if _, err := s.RecordNodeName(nodeInfoResult(0x11223344, "", "ALFA"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("second RecordNodeName: %v", err)
	}

	got, _ := s.LookupNodeName(0x11223344)
	if got.LongName != "Alpha Node" {
		t.Errorf("LongName = %q after a frame that did not state it; want the known name kept", got.LongName)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// And the same after a restart, so the kept value really reached the table.
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if long, _, _ := reopened.NodeNameFor(0x11223344); long != "Alpha Node" {
		t.Errorf("after reopen LongName = %q, want the known name kept in the table", long)
	}
}

// TestRecordNodeName_ShortNameOnlyNodeIsStillNamed: a node that set only a short
// name is a named node, and Display falls back to it.
func TestRecordNodeName_ShortNameOnlyNodeIsStillNamed(t *testing.T) {
	s := openTestStore(t)

	if _, err := s.RecordNodeName(nodeInfoResult(0x55667788, "   ", "BRVO"), time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}
	got, ok := s.LookupNodeName(0x55667788)
	if !ok {
		t.Fatal("a node with only a short name was not recorded")
	}
	if got.LongName != "" {
		t.Errorf("LongName = %q, want empty", got.LongName)
	}
	if got.Display() != "BRVO" {
		t.Errorf("Display = %q, want the short name", got.Display())
	}
}

// TestNormalizeName covers every kind of "name" a radio can broadcast, because
// this one function is what every surface relies on to decide whether a node has
// a name at all. Korean text and emoji are real names and must survive; things
// nobody can see must not.
func TestNormalizeName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Alpha Node", "Alpha Node"},
		{"  Alpha Node  ", "Alpha Node"},
		{"한글 이름", "한글 이름"},
		{"Node 📡", "Node 📡"},
		{" ", ""},
		{"\t\n", ""},
		{"\u200b\u200b", ""},
		{"\u0000", ""},
		{"Alpha\u0000 Node", "Alpha Node"},
		{"A\u200bB", "AB"},
	} {
		if got := normalizeName(c.in); got != c.want {
			t.Errorf("normalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
