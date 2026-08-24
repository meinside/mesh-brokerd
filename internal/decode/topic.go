package decode

import (
	"fmt"
	"strings"
)

// Topic is a parsed MQTT topic. Two grammars exist
// (docs/protocol-spec.md §1):
//
//	{mqtt.root}/2/e/{channel}/{node}   ordinary packets
//	{mqtt.root}/2/map/                 map reports
//
// Root itself is a multi-segment prefix (e.g. this project's "msh/pvt"),
// so it cannot be split on "/" naively from the front — this parser
// anchors on the fixed literal segments instead and takes everything
// before them as Root.
type Topic struct {
	Root    string
	Channel string // topic's {channel} segment, verbatim — opaque, never parsed further. Empty for a map report.
	Node    string // topic's {node} segment, verbatim — the gateway's "!hex" node ID. Empty for a map report.

	// IsMapReport marks the {root}/2/map/ grammar, which carries neither a
	// channel nor a node segment: the firmware puts the primary channel's
	// name in the ServiceEnvelope's channel_id instead
	// (docs/firmware-config.md §14).
	IsMapReport bool
}

// ParseTopic parses a full MQTT topic string. Returns an error if the
// topic matches neither grammar.
func ParseTopic(topic string) (Topic, error) {
	segs := strings.Split(topic, "/")

	// Map report: {root}/2/map/ — the trailing slash means the final
	// segment is empty, so "2", "map", "" are the last three.
	if len(segs) >= 4 && segs[len(segs)-1] == "" && segs[len(segs)-2] == "map" && segs[len(segs)-3] == "2" {
		root := strings.Join(segs[:len(segs)-3], "/")
		if root == "" {
			return Topic{}, fmt.Errorf("decode: topic %q has an empty root", topic)
		}
		return Topic{Root: root, IsMapReport: true}, nil
	}

	if len(segs) < 4 {
		return Topic{}, fmt.Errorf("decode: topic %q has too few segments for {root}/2/e/{channel}/{node}", topic)
	}

	node := segs[len(segs)-1]
	channel := segs[len(segs)-2]
	litE := segs[len(segs)-3]
	lit2 := segs[len(segs)-4]

	if litE != "e" || lit2 != "2" {
		return Topic{}, fmt.Errorf("decode: topic %q does not match {root}/2/e/{channel}/{node} (found %q/%q where 2/e expected)", topic, lit2, litE)
	}

	root := strings.Join(segs[:len(segs)-4], "/")
	if root == "" {
		return Topic{}, fmt.Errorf("decode: topic %q has an empty root", topic)
	}

	return Topic{Root: root, Channel: channel, Node: node}, nil
}
