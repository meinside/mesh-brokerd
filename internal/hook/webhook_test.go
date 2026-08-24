package hook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
)

// TestWebhookSink_SignsTheExactBody checks the receiver's side of the
// contract: the signature must verify over the bytes as sent, so a
// receiver can reject anything brokerd did not produce.
func TestWebhookSink_SignsTheExactBody(t *testing.T) {
	const secret = "test-secret"
	body := []byte(`{"event":"frame","board_id":"alpha"}`)

	var (
		mu       sync.Mutex
		gotBody  []byte
		gotSig   string
		gotDeliv string
		gotType  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody, gotSig, gotDeliv, gotType = b, r.Header.Get(SignatureHeader), r.Header.Get(DeliveryHeader), r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := NewWebhookSink().Deliver(context.Background(), config.HookTarget{
		Name: "w", Kind: config.HookKindWebhook, URL: srv.URL, Secret: secret, Timeout: 5 * time.Second,
	}, body)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if string(gotBody) != string(body) {
		t.Errorf("body = %q, want %q", gotBody, body)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Errorf("signature = %q, want %q", gotSig, want)
	}
	if gotDeliv == "" {
		t.Error("delivery id header missing")
	}
	if gotType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotType)
	}
}

func TestWebhookSink_UnsignedWhenNoSecret(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewWebhookSink().Deliver(context.Background(), config.HookTarget{
		Name: "w", Kind: config.HookKindWebhook, URL: srv.URL, Timeout: 5 * time.Second,
	}, []byte("{}")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got != "" {
		t.Errorf("signature header present without a configured secret: %q", got)
	}
}

func TestWebhookSink_NonSuccessStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := NewWebhookSink().Deliver(context.Background(), config.HookTarget{
		Name: "w", Kind: config.HookKindWebhook, URL: srv.URL, Timeout: 5 * time.Second,
	}, []byte("{}"))
	if err == nil {
		t.Error("Deliver returned nil for HTTP 500")
	}
}

// TestDispatch_RetriesWebhookThenSucceeds covers the one place retries are
// allowed: a webhook, where re-POSTing is what the receiver expects.
func TestDispatch_RetriesWebhookThenSucceeds(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 2 {
			http.Error(w, "later", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := config.HookTarget{
		Name: "w", Kind: config.HookKindWebhook, Enabled: true, URL: srv.URL,
		Timeout: 5 * time.Second, Retries: 2, QuietFrom: -1, QuietTo: -1,
		Match: config.HookMatch{Events: []string{config.HookEventFrame}},
	}
	d := New(Options{
		Config: config.EventHooks{Enabled: true, DryRun: false, QueueSize: 4, MaxConcurrent: 1,
			Targets: []config.HookTarget{target}},
		Logger: quietLogger(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	d.Run(ctx)
	defer func() { cancel(); d.Wait() }()

	e, raw := testFrame("x")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return d.Snapshot().Fired["w"] == 1 })

	mu.Lock()
	defer mu.Unlock()
	if attempts != 2 {
		t.Errorf("server saw %d attempts, want 2 (one failure then a retry)", attempts)
	}
}

// TestWebhookSink_SendsConfiguredHeaders covers a receiver that refuses a
// request without one. Several chat services require a vendor-specific Accept
// header and ignore anything else.
func TestWebhookSink_SendsConfiguredHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := NewWebhookSink().Deliver(context.Background(), config.HookTarget{
		Name: "w", Kind: config.HookKindWebhook, URL: srv.URL, Timeout: 5 * time.Second,
		Headers: map[string]string{
			"Accept":       "application/vnd.example-chat-v2+json",
			"Content-Type": "application/json; charset=utf-8", // overrides the default
		},
	}, []byte("{}"))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if v := got.Get("Accept"); v != "application/vnd.example-chat-v2+json" {
		t.Errorf("Accept = %q, want the configured value", v)
	}
	if v := got.Get("Content-Type"); v != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q; a configured header must be able to override a default", v)
	}
	// brokerd's own headers survive alongside.
	if got.Get(DeliveryHeader) == "" {
		t.Error("delivery id header lost when custom headers were set")
	}
}

// TestRender_JSONFunctionEscapes is the reason the json function exists: a
// mesh message is arbitrary text from whoever is in radio range, and one
// quote would otherwise turn a chat notification into a 400 from the receiver.
func TestRender_JSONFunctionEscapes(t *testing.T) {
	target := frameTarget()
	target.Match.IncludeText = true
	target.Template = `{"body": {{json (index .Fields "text")}}, "connectColor": "#2196F3"}`

	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, time.Now)

	nasty := "he said \"hi\"\nthen left \\ home\ttab"
	e, raw := testFrame(nasty)
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	body := sink.bodies[0]
	var decoded struct {
		Body         string `json:"body"`
		ConnectColor string `json:"connectColor"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v\n%s", err, body)
	}
	if decoded.Body != nasty {
		t.Errorf("body = %q, want the message verbatim after escaping", decoded.Body)
	}
	if decoded.ConnectColor != "#2196F3" {
		t.Errorf("connectColor = %q", decoded.ConnectColor)
	}
}

// TestRender_TruncKeepsUTF8Intact: a receiver with a length limit must not be
// handed a message cut in the middle of a multi-byte character.
func TestRender_TruncKeepsUTF8Intact(t *testing.T) {
	target := frameTarget()
	target.Match.IncludeText = true
	target.Template = `{"body": {{json (trunc 3 (index .Fields "text"))}}}`

	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, time.Now)

	e, raw := testFrame("가나다라마")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	var decoded struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(sink.bodies[0], &decoded); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if decoded.Body != "가나다…" {
		t.Errorf("body = %q, want the first three runes plus an ellipsis", decoded.Body)
	}
}

// fakeNames is a NameResolver that knows about exactly one node.
type fakeNames struct {
	id          uint32
	long, short string
}

func (f fakeNames) NodeNameFor(id uint32) (string, string, bool) {
	if id != f.id {
		return "", "", false
	}
	return f.long, f.short, true
}

// TestAttachNodeNames_OnlyStatesWhatIsKnown: a receiver must be able to tell a
// node that has introduced itself from one that has not, so an unknown node
// leaves the fields absent instead of echoing the id back as a name.
func TestAttachNodeNames_OnlyStatesWhatIsKnown(t *testing.T) {
	names := fakeNames{id: 0x11223344, long: "Alpha Node", short: "ALFA"}

	known := Event{FromNode: "0x11223344"}
	known.AttachNodeNames(names, 0x11223344, 0x55667788)
	if known.FromLongName != "Alpha Node" || known.FromShortName != "ALFA" {
		t.Errorf("known sender: long=%q short=%q", known.FromLongName, known.FromShortName)
	}
	if known.ToLongName != "" {
		t.Errorf("ToLongName = %q for a node nothing is known about", known.ToLongName)
	}

	unknown := Event{FromNode: "0x55667788"}
	unknown.AttachNodeNames(names, 0x55667788, 0)
	if unknown.FromLongName != "" || unknown.FromShortName != "" {
		t.Errorf("unknown sender got a name: %+v", unknown)
	}

	// No resolver at all (a fresh deployment, or the -test-hooks self test).
	var nilSafe Event
	nilSafe.AttachNodeNames(nil, 0x11223344, 0)
	if nilSafe.FromLongName != "" {
		t.Error("a nil resolver produced a name")
	}

	// The name and the id are separate fields. The name carries the short name
	// -- which the combined label used to hide -- and the id is present even
	// for a node nothing is known about, so a consumer always has something
	// to identify the sender by.
	if known.FromName != "Alpha Node (ALFA)" {
		t.Errorf("FromName = %q, want the long name with the short name after it", known.FromName)
	}
	if known.FromID != "!11223344" {
		t.Errorf("FromID = %q", known.FromID)
	}
	if unknown.FromName != "" {
		t.Errorf("FromName = %q for an unnamed node, want empty: the id is a separate field", unknown.FromName)
	}
	if unknown.FromID != "!55667788" {
		t.Errorf("FromID = %q for an unnamed node, want the id anyway", unknown.FromID)
	}
	if nilSafe.FromID != "!11223344" || nilSafe.FromName != "" {
		t.Errorf("with no resolver: FromID = %q, FromName = %q", nilSafe.FromID, nilSafe.FromName)
	}

	// A node that set only a short name is still named by it.
	shortOnly := Event{}
	shortOnly.AttachNodeNames(fakeNames{id: 0x11223344, short: "ALFA"}, 0x11223344, 0)
	if shortOnly.FromName != "ALFA" {
		t.Errorf("FromName = %q, want the short name on its own", shortOnly.FromName)
	}

	// The absent fields must not appear in the JSON at all.
	body, err := json.Marshal(unknown)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(body), "from_long_name") {
		t.Errorf("payload states an empty name key: %s", body)
	}
	body, err = json.Marshal(known)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(body), `"from_long_name":"Alpha Node"`) {
		t.Errorf("payload omits a known name: %s", body)
	}
}

// TestFormatNodeName_NeverShowsEmptyBrackets: storage normalises a
// whitespace-only name to "", so the formatter has to treat that as absent
// rather than emitting "Alpha Node ()" or " (ALFA)", either of which reads as a
// broken lookup.
func TestFormatNodeName_NeverShowsEmptyBrackets(t *testing.T) {
	cases := []struct {
		name        string
		long, short string
		want        string
	}{
		{"both known", "Alpha Node", "ALFA", "Alpha Node (ALFA)"},
		{"only short", "", "ALFA", "ALFA"},
		{"only long", "Alpha Node", "", "Alpha Node"},
		{"neither", "", "", ""},
	}
	for _, c := range cases {
		if got := decode.FormatNodeName(c.long, c.short); got != c.want {
			t.Errorf("%s: FormatNodeName(%q, %q) = %q, want %q", c.name, c.long, c.short, got, c.want)
		}
	}
}

// TestAttachNodeNames_ResolverReturningEmptyNames guards the seam between the
// packages: a resolver that reports ok with empty strings must not put empty
// name keys in the payload nor an empty name in the label.
func TestAttachNodeNames_ResolverReturningEmptyNames(t *testing.T) {
	var e Event
	e.AttachNodeNames(okButEmptyNames{}, 0x11223344, 0)

	if e.FromLongName != "" || e.FromShortName != "" {
		t.Errorf("empty names were attached: %+v", e)
	}
	if e.FromName != "" {
		t.Errorf("FromName = %q, want empty when the resolver reports empty names", e.FromName)
	}
	if e.FromID != "!11223344" {
		t.Errorf("FromID = %q, want the id", e.FromID)
	}
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{"from_long_name", "from_short_name", "from_name"} {
		if strings.Contains(string(body), key) {
			t.Errorf("payload states %q with an empty value: %s", key, body)
		}
	}
}

type okButEmptyNames struct{}

func (okButEmptyNames) NodeNameFor(uint32) (string, string, bool) { return "", "", true }
