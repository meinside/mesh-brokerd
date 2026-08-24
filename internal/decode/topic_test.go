package decode

import "testing"

func TestParseTopic(t *testing.T) {
	cases := []struct {
		topic   string
		wantErr bool
		root    string
		channel string
		node    string
	}{
		{"msh/pvt/2/e/pvt/!11223344", false, "msh/pvt", "pvt", "!11223344"},
		{"msh/KR/2/e/pvt-test-a/!11223344", false, "msh/KR", "pvt-test-a", "!11223344"},
		{"msh/KR/2/e/PKI/!11223344", false, "msh/KR", "PKI", "!11223344"},
		{"2/e/pvt/!11223344", true, "", "", ""}, // no root at all
		{"too/short", true, "", "", ""},
		{"msh/pvt/9/e/pvt/!11223344", true, "", "", ""}, // wrong literal
	}

	for _, c := range cases {
		got, err := ParseTopic(c.topic)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseTopic(%q): want error, got %+v", c.topic, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTopic(%q): unexpected error: %v", c.topic, err)
			continue
		}
		if got.Root != c.root || got.Channel != c.channel || got.Node != c.node {
			t.Errorf("ParseTopic(%q) = %+v, want {Root:%s Channel:%s Node:%s}", c.topic, got, c.root, c.channel, c.node)
		}
	}
}

// Note: nonce derivation and captured-plaintext parsing are asserted
// against the real hardware fixtures in decode_test.go's
// TestCaptureFixtures, driven by testdata/ rather than duplicated as
// hardcoded literals here.

func TestIsPKIEncrypted(t *testing.T) {
	cases := []struct {
		name string
		env  ServiceEnvelope
		mp   MeshPacket
		want bool
	}{
		{"reserved channel_id", ServiceEnvelope{ChannelID: "PKI"}, MeshPacket{}, true},
		{"pki_encrypted flag", ServiceEnvelope{ChannelID: "pvt"}, MeshPacket{PKIEncrypted: true}, true},
		{"neither", ServiceEnvelope{ChannelID: "pvt"}, MeshPacket{}, false},
	}
	for _, c := range cases {
		if got := IsPKIEncrypted(&c.env, &c.mp); got != c.want {
			t.Errorf("%s: IsPKIEncrypted = %v, want %v", c.name, got, c.want)
		}
	}
}

// The map-report topic is a second, shorter grammar: {root}/2/map/ with no
// channel or node segment. Observed live as "msh/pvt/2/map/" (trailing
// slash), and confirmed from firmware source, which builds it as
// root + "/2/map/" and sets the ServiceEnvelope's channel_id to the primary
// channel instead (docs/firmware-config.md §14).
//
// Before this was handled, brokerd dropped every map report at
// decode.Decode with "topic did not match expected grammar" — the packets
// had been arriving correctly for hours while looking, from raw_frames,
// exactly like a board that was not publishing at all.
func TestParseTopic_MapReport(t *testing.T) {
	cases := []struct {
		topic    string
		wantRoot string
	}{
		{"msh/pvt/2/map/", "msh/pvt"},
		{"msh/KR/2/map/", "msh/KR"},
		{"msh/2/map/", "msh"},
	}
	for _, c := range cases {
		got, err := ParseTopic(c.topic)
		if err != nil {
			t.Errorf("ParseTopic(%q) returned error: %v", c.topic, err)
			continue
		}
		if !got.IsMapReport {
			t.Errorf("ParseTopic(%q).IsMapReport = false, want true", c.topic)
		}
		if got.Root != c.wantRoot {
			t.Errorf("ParseTopic(%q).Root = %q, want %q", c.topic, got.Root, c.wantRoot)
		}
		if got.Channel != "" || got.Node != "" {
			t.Errorf("ParseTopic(%q) set Channel=%q Node=%q; a map topic has neither", c.topic, got.Channel, got.Node)
		}
	}
}

// The two grammars must not bleed into each other.
func TestParseTopic_MapReportDoesNotLoosenTheMainGrammar(t *testing.T) {
	for _, topic := range []string{
		"msh/pvt/2/map",       // no trailing slash: not the map topic
		"msh/pvt/2/map/extra", // deeper than the map topic
		"msh/pvt/3/map/",      // wrong literal
	} {
		if got, err := ParseTopic(topic); err == nil && got.IsMapReport {
			t.Errorf("ParseTopic(%q) was accepted as a map topic", topic)
		}
	}
}

// An ordinary packet topic must still report IsMapReport = false.
func TestParseTopic_NormalTopicIsNotMapReport(t *testing.T) {
	got, err := ParseTopic("msh/pvt/2/e/pvt/!abcd1234")
	if err != nil {
		t.Fatalf("ParseTopic: %v", err)
	}
	if got.IsMapReport {
		t.Error("a {root}/2/e/... topic was reported as a map topic")
	}
}
