//go:build diag

package decode

import (
	"bufio"
	"encoding/hex"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestDiagPublicTrafficPortnums decodes a capture of the official public
// MQTT server's default-channel traffic and reports which portnums actually
// appear, and how many distinct nodes send each.
//
// Run against a file of "topic hexpayload" lines (one per message):
//
//	DIAG_CAPTURE=/tmp/us.txt CGO_ENABLED=1 \
//	  go test -tags diag ./internal/decode/... -run TestDiagPublicTrafficPortnums -v
//
// Purpose: answer "does a node have to send NODEINFO_APP to be usable by
// public consumers?" from real traffic rather than from documentation, and
// compare the field set of real uplinked packets against what brokerd's own
// relay constructs (docs/outbound-relay.md §4.2).
//
// The default channel key is a published protocol constant, not a secret
// (DefaultChannelPSK), so this needs no credentials of ours.
func TestDiagPublicTrafficPortnums(t *testing.T) {
	path := os.Getenv("DIAG_CAPTURE")
	if path == "" {
		t.Fatal("DIAG_CAPTURE not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening capture: %v", err)
	}
	defer func() { _ = f.Close() }()

	dpsk := DefaultChannelPSK
	psk := dpsk[:]

	type stat struct {
		messages int
		nodes    map[uint32]bool
	}
	byPort := map[string]*stat{}
	fieldCounts := map[int]int{}
	var total, envFail, decFail int

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) != 2 {
			continue
		}
		total++
		raw, err := hex.DecodeString(parts[1])
		if err != nil {
			continue
		}
		env, err := ParseServiceEnvelope(raw)
		if err != nil {
			envFail++
			continue
		}
		mp, err := ParseMeshPacket(env.PacketBytes)
		if err != nil {
			envFail++
			continue
		}
		// Record which optional envelope fields real traffic carries.
		if mp.RxTime != 0 {
			fieldCounts[7]++
		}
		if mp.HopLimit != 0 {
			fieldCounts[9]++
		}
		if mp.Priority != 0 {
			fieldCounts[11]++
		}
		if mp.HopStart != 0 {
			fieldCounts[15]++
		}
		if mp.RelayNode != 0 {
			fieldCounts[19]++
		}

		var plain []byte
		switch {
		case len(mp.Decoded) > 0:
			plain = mp.Decoded
		case len(mp.Encrypted) > 0:
			p, err := DecryptChannelPacket(psk, mp.ID, mp.From, mp.Encrypted)
			if err != nil {
				decFail++
				continue
			}
			plain = p
		default:
			continue
		}
		data, err := ParseData(plain)
		if err != nil {
			decFail++
			continue
		}
		name := portnumLabel(PortNum(data.Portnum))
		s := byPort[name]
		if s == nil {
			s = &stat{nodes: map[uint32]bool{}}
			byPort[name] = s
		}
		s.messages++
		s.nodes[mp.From] = true
	}

	t.Logf("messages=%d envelope_parse_failed=%d decode_failed=%d", total, envFail, decFail)

	names := make([]string, 0, len(byPort))
	for n := range byPort {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return byPort[names[i]].messages > byPort[names[j]].messages })
	for _, n := range names {
		t.Logf("  %-28s messages=%-6d distinct_nodes=%d", n, byPort[n].messages, len(byPort[n].nodes))
	}

	t.Logf("optional MeshPacket fields present, out of %d messages:", total)
	for _, f := range []int{7, 9, 11, 15, 19} {
		t.Logf("  field %-2d present in %d", f, fieldCounts[f])
	}
}

// portnumLabel gives a stable label for the report without depending on a
// String method this package may not expose.
func portnumLabel(p PortNum) string {
	switch p {
	case PortNumTextMessage:
		return "TEXT_MESSAGE_APP(1)"
	case PortNumPosition:
		return "POSITION_APP(3)"
	default:
		return "portnum " + itoa(int(p))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
