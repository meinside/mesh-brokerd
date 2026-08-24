package broker

import (
	"log/slog"
	"sync"

	mqtt "github.com/mochi-mqtt/server/v2"
)

// ACLDenialLogger makes ACL refusals visible. It answers only
// OnACLCheck, always with false, and exists purely to log and count.
//
// Why it is needed: mochi-mqtt handles a publish that fails the ACL by
// returning early, and for QoS 0 it returns *silently* --
//
//	if !cl.Net.Inline && !s.hooks.OnACLCheck(cl, pk.TopicName, true) {
//	    if pk.FixedHeader.Qos == 0 {
//	        return nil
//	    }
//
// -- with no log line, no counter and no disconnect. Meshtastic publishes
// at QoS 0, so a board whose topic falls outside its ACL is refused in a
// way that is indistinguishable, from the server side, from the board
// never having published at all. That ambiguity has cost a real
// investigation here (docs/runbook.md section 8): no signal is a claim
// that needs its own evidence.
//
// Why returning false is safe -- and mandatory: mochi-mqtt combines
// OnACLCheck across hooks as an OR that stops at the first hook to
// return true (server/hooks.go). A hook returning true would therefore
// *grant* access the ledger had refused. Returning false leaves the
// verdict exactly as it was.
//
// Why registration order matters: because of that same OR, a hook
// registered after the ACL ledger is only reached when the ledger has
// already refused. That is what makes this hook a denial observer rather
// than a log of every ACL check. It must stay last
// (TestBroker_ACLDenialIsObservable covers the observable effect).
//
// Logging policy matches the project's other report-only checks
// (permcheck.go, NodeIDChecker): one line per distinct
// (client, topic, direction), so a misconfigured board cannot flood the
// log, while the counter keeps rising so docs/monitoring-api.md still
// shows it is ongoing.
type ACLDenialLogger struct {
	mqtt.HookBase

	log *slog.Logger

	mu          sync.Mutex
	logged      map[string]bool  // "username|topic|direction" -> already logged
	denials     map[string]int64 // username -> occurrences
	capReported bool             // the "too many keys" warning is itself logged once
}

// maxLoggedACLKeys bounds the log-once table. The keys include the topic, so
// a client refused across many topics would otherwise grow it forever. The
// number only has to be larger than any legitimate deployment's distinct
// (account, topic, direction) triples, which for this project is a handful.
const maxLoggedACLKeys = 1000

// NewACLDenialLogger builds the hook. A nil logger falls back to the
// default so a denial is never lost to a nil dereference.
func NewACLDenialLogger(log *slog.Logger) *ACLDenialLogger {
	if log == nil {
		log = slog.Default()
	}
	return &ACLDenialLogger{
		log:     log,
		logged:  make(map[string]bool),
		denials: make(map[string]int64),
	}
}

func (h *ACLDenialLogger) ID() string { return "brokerd-acl-denial-logger" }

// Provides deliberately answers OnACLCheck only. Answering
// OnConnectAuthenticate would make this hook part of the authentication
// OR, where returning anything but false is a hole
// (TestACLDenialLogger_ProvidesOnlyACLCheck).
func (h *ACLDenialLogger) Provides(b byte) bool {
	return b == mqtt.OnACLCheck
}

// OnACLCheck records a refusal and returns false, leaving the refusal in
// place. It is only reached for topics every earlier hook has already
// refused (see the type comment on registration order).
func (h *ACLDenialLogger) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	username := "<unknown>"
	if cl != nil && len(cl.Properties.Username) > 0 {
		username = string(cl.Properties.Username)
	}
	direction := "subscribe"
	if write {
		direction = "publish"
	}

	h.mu.Lock()
	h.denials[username]++
	// logged exists to log each distinct refusal once. Its keys include the
	// topic, so a client refused on many topics would grow it without
	// bound -- a slow leak in the one component that must not fall over.
	// Past the cap it stops tracking and stops logging; the per-username
	// counter keeps counting, which is what the monitoring API exposes.
	key := username + "|" + topic + "|" + direction
	first := false
	switch {
	case h.logged[key]:
	case len(h.logged) < maxLoggedACLKeys:
		h.logged[key] = true
		first = true
	case !h.capReported:
		h.capReported = true
		first = true
		h.log.Warn("acl: too many distinct refusals to log individually",
			"distinct_keys", len(h.logged),
			"note", "further refusals are counted in acl_denials_total but no longer logged")
	}
	h.mu.Unlock()

	if first {
		// WARN, not ERROR: for a scanner or a stray client this is the ACL
		// working as designed. It is only a fault when the client is one of
		// our own boards, which is why the username is on the line.
		h.log.Warn("acl: refused",
			"username", username,
			"topic", topic,
			"direction", direction,
			"note", "MQTT QoS 0 gives the client no error, so this line is the only record")
	}
	return false
}

// Denials returns a copy of the per-client denial counters
// (docs/monitoring-api.md's acl_denials_total).
func (h *ACLDenialLogger) Denials() map[string]int64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make(map[string]int64, len(h.denials))
	for k, v := range h.denials {
		out[k] = v
	}
	return out
}
