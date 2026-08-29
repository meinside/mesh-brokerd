package broker

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

func subPacket(filters ...string) packets.Packet {
	pk := packets.Packet{}
	for _, f := range filters {
		pk.Filters = append(pk.Filters, packets.Subscription{Filter: f})
	}
	return pk
}

func testClient(username string) *mqtt.Client {
	cl := &mqtt.Client{}
	cl.Properties.Username = []byte(username)
	return cl
}

// countingInfoHandler counts INFO records, for the "logged once" assertion.
type countingInfoHandler struct{ n *int }

func (h countingInfoHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= slog.LevelInfo
}
func (h countingInfoHandler) Handle(_ context.Context, _ slog.Record) error {
	*h.n++
	return nil
}
func (h countingInfoHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h countingInfoHandler) WithGroup(_ string) slog.Handler      { return h }

// TestSubscriptionTracker_RecordsWhatABoardAskedToReceive is the case the
// tracker exists for: two accounts, and one of them never mentions a channel
// the other does. Nothing else in brokerd can see that -- the ACL refused
// nothing, both boards are connected, and both publish normally.
func TestSubscriptionTracker_RecordsWhatABoardAskedToReceive(t *testing.T) {
	tr := NewSubscriptionTracker(slog.New(countingInfoHandler{n: new(int)}))

	tr.OnSubscribed(testClient("alpha"), subPacket("msh/pvt/2/e/second/+", "msh/pvt/2/e/first/+"), nil)
	tr.OnSubscribed(testClient("bravo"), subPacket("msh/pvt/2/e/first/+"), nil)

	got := tr.Subscriptions()
	// Reported verbatim and sorted, so a comparison is stable and the topic's
	// channel segment is never parsed.
	if len(got["alpha"]) != 2 ||
		got["alpha"][0] != "msh/pvt/2/e/first/+" || got["alpha"][1] != "msh/pvt/2/e/second/+" {
		t.Errorf("alpha subscriptions = %v, want both filters sorted", got["alpha"])
	}
	if len(got["bravo"]) != 1 || got["bravo"][0] != "msh/pvt/2/e/first/+" {
		t.Errorf("bravo subscriptions = %v, want only the one channel it asked for", got["bravo"])
	}
}

// A board reconnects with cleanSession and resubscribes every time, dozens of
// times a day here. The report must not grow duplicates and the log must not
// repeat a filter it already reported.
func TestSubscriptionTracker_ResubscribeIsIdempotent(t *testing.T) {
	var lines int
	tr := NewSubscriptionTracker(slog.New(countingInfoHandler{n: &lines}))

	for range 3 {
		tr.OnSubscribed(testClient("alpha"), subPacket("msh/pvt/2/e/first/+"), nil)
	}

	if got := tr.Subscriptions()["alpha"]; len(got) != 1 {
		t.Errorf("Subscriptions()[alpha] = %v, want one entry after three identical SUBSCRIBEs", got)
	}
	if lines != 1 {
		t.Errorf("logged %d lines for three identical SUBSCRIBEs, want 1", lines)
	}
}

func TestSubscriptionTracker_UnsubscribeRemovesTheFilter(t *testing.T) {
	tr := NewSubscriptionTracker(slog.New(countingInfoHandler{n: new(int)}))

	tr.OnSubscribed(testClient("alpha"), subPacket("a/b", "c/d"), nil)
	tr.OnUnsubscribed(testClient("alpha"), subPacket("a/b"))

	got := tr.Subscriptions()["alpha"]
	if len(got) != 1 || got[0] != "c/d" {
		t.Errorf("Subscriptions()[alpha] = %v, want only c/d", got)
	}

	tr.OnUnsubscribed(testClient("alpha"), subPacket("c/d"))
	if _, present := tr.Subscriptions()["alpha"]; present {
		t.Error("an account with no filters left is still reported")
	}
}

func TestSubscriptionTracker_IgnoresAClientWithNoUsername(t *testing.T) {
	tr := NewSubscriptionTracker(slog.New(countingInfoHandler{n: new(int)}))

	tr.OnSubscribed(&mqtt.Client{}, subPacket("a/b"), nil)

	if len(tr.Subscriptions()) != 0 {
		t.Errorf("Subscriptions() = %v, want empty for a client with no username", tr.Subscriptions())
	}
}

func TestSubscriptionTracker_SubscriptionsAreCopied(t *testing.T) {
	tr := NewSubscriptionTracker(slog.New(countingInfoHandler{n: new(int)}))
	tr.OnSubscribed(testClient("alpha"), subPacket("a/b"), nil)

	m := tr.Subscriptions()
	m["alpha"][0] = "mutated"
	m["injected"] = []string{"x"}

	again := tr.Subscriptions()
	if again["alpha"][0] != "a/b" {
		t.Errorf("Subscriptions() shares its slices with the caller: %v", again["alpha"])
	}
	if _, present := again["injected"]; present {
		t.Error("Subscriptions() returned an aliased map")
	}
}

func TestSubscriptionTracker_ProvidesOnlySubscriptionHooks(t *testing.T) {
	tr := NewSubscriptionTracker(slog.New(countingInfoHandler{n: new(int)}))

	for _, b := range []byte{mqtt.OnSubscribed, mqtt.OnUnsubscribed} {
		if !tr.Provides(b) {
			t.Errorf("Provides(%d) = false, want true", b)
		}
	}
	// Anything else would put this hook on a path where returning the wrong
	// thing can refuse a connection or a publish. It only ever observes.
	for _, b := range []byte{mqtt.OnConnect, mqtt.OnPublish, mqtt.OnACLCheck, mqtt.OnConnectAuthenticate} {
		if tr.Provides(b) {
			t.Errorf("Provides(%d) = true, want false — this hook must only observe", b)
		}
	}
}

// TestBroker_ReportsARealClientsSubscription proves the hook is attached to the
// running server, not merely correct in isolation: this project has shipped a
// correct predicate that no caller consulted. An unregistered tracker reports an
// empty set forever, which is indistinguishable from "no board ever subscribed"
// -- the very confusion it exists to remove. So it is driven through a real
// client over a real listener.
func TestBroker_ReportsARealClientsSubscription(t *testing.T) {
	sink := &syncBuffer{}
	addr := serveAuthBroker(t, sink, "alpha", "correct-horse")

	opts := paho.NewClientOptions().
		AddBroker("tcp://" + addr).
		SetClientID("subscription-probe").
		SetUsername("alpha").
		SetPassword("correct-horse").
		SetConnectTimeout(5 * time.Second).
		SetConnectRetry(false).
		SetAutoReconnect(false)
	cl := paho.NewClient(opts)
	if tok := cl.Connect(); tok.WaitTimeout(5*time.Second) && tok.Error() != nil {
		t.Fatalf("connect: %v", tok.Error())
	}
	defer cl.Disconnect(100)

	const filter = "msh/pvt/2/e/pvt/+"
	if tok := cl.Subscribe(filter, 0, nil); tok.WaitTimeout(5*time.Second) && tok.Error() != nil {
		t.Fatalf("subscribe: %v", tok.Error())
	}

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(sink.String(), "board subscribed") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	logged := sink.String()
	if !strings.Contains(logged, "board subscribed") {
		t.Fatalf("a real client's subscription was not observed; log was:\n%s", logged)
	}
	if !strings.Contains(logged, filter) {
		t.Errorf("the log line does not name the filter; log was:\n%s", logged)
	}
	if !strings.Contains(logged, "alpha") {
		t.Errorf("the log line does not name the account; log was:\n%s", logged)
	}
}
