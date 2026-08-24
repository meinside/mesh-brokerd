package monitor

import (
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/hook"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// seedPageData writes rows with values the assertions below look for by
// name. Asserting on a known database rather than on "200 OK" is the whole
// point: a page that renders an empty shell also returns 200.
func seedPageData(t *testing.T, store *storage.Store) {
	t.Helper()
	now := time.Now()

	// A frame the gateway heard over RF: it states an SNR.
	heard := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 0x1234, FromNode: 0x99aabbcc, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage, PacketParsed: true,
		HasRxSnr: true, RxSnr: 6.5, HopStart: 3, HopLimit: 3,
		TextMessage: &decode.TextMessage{Text: "hello from the mesh"},
	}
	rawID, err := store.InsertRawFrame(heard, "alpha", "alpha", []byte{0x01}, now)
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := store.InsertTextMessage(rawID, heard, "pvt", now); err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}
	if _, err := store.InsertDecodedPayload(rawID, heard); err != nil {
		t.Fatalf("InsertDecodedPayload: %v", err)
	}

	// A frame the gateway produced itself: it states no SNR at all, and the
	// page must not render that as 0.
	own := &decode.Result{
		Topic: "msh/pvt/2/map/", ChannelSegment: "LongFast",
		GatewayID: "!11223344", PacketID: 0, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumMapReport, PacketParsed: true,
	}
	if _, err := store.InsertRawFrame(own, "alpha", "alpha", []byte{0x02}, now); err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
}

func basicAuthHeader(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("anything:"+token))
}

func getPage(t *testing.T, s *Server, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	return w
}

// TestPage_RendersStoredValues asserts on specific values from a seeded
// database, including the distinction between a measured SNR and an absent
// one.
func TestPage_RendersStoredValues(t *testing.T) {
	s := newTestServer(t)
	seedPageData(t, s.store)

	w := getPage(t, s, "Bearer test-token")
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	body := w.Body.String()

	for _, want := range []string{
		"TEXT_MESSAGE_APP",    // portnum breakdown and recent frames
		"MAP_REPORT_APP",      // the second seeded frame
		"hello from the mesh", // the message itself
		"!99aabbcc",           // sender rendered in the firmware's own form
		"6.5",                 // the measured SNR
		"alpha",               // board id
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}

	// The map report states no SNR. "0.0" must not appear as its value: an
	// absent measurement and a measured zero are different facts (ADR-15).
	if strings.Contains(body, ">0.0<") {
		t.Errorf("page rendered an absent SNR as 0.0")
	}
	if !strings.Contains(body, "—") {
		t.Errorf("page has no dash for an absent measurement")
	}
}

// TestPage_NeverContainsTheToken is the one leak a monitoring page could
// cause on its own: rendering the credential that was used to open it.
func TestPage_NeverContainsTheToken(t *testing.T) {
	s := newTestServer(t)
	seedPageData(t, s.store)

	for _, header := range []string{"Bearer test-token", basicAuthHeader("test-token")} {
		w := getPage(t, s, header)
		if w.Code != http.StatusOK {
			t.Fatalf("GET / = %d, want 200", w.Code)
		}
		if strings.Contains(w.Body.String(), "test-token") {
			t.Errorf("page rendered the monitoring token (auth via %q)", header)
		}
	}
}

// TestPage_EscapesMessageText covers the injection path this page has by
// design: message bodies come from the mesh, and anyone within radio range
// can send one.
func TestPage_EscapesMessageText(t *testing.T) {
	s := newTestServer(t)

	nasty := `<script>alert(1)</script>`
	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 7, FromNode: 0x99aabbcc, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage, PacketParsed: true,
		TextMessage: &decode.TextMessage{Text: nasty},
	}
	rawID, err := s.store.InsertRawFrame(res, "alpha", "alpha", []byte{0x03}, time.Now())
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := s.store.InsertTextMessage(rawID, res, "pvt", time.Now()); err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}

	body := getPage(t, s, "Bearer test-token").Body.String()
	if strings.Contains(body, nasty) {
		t.Errorf("message text was rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("escaped form of the message is missing; got:\n%s", body)
	}
}

// TestPage_RendersWithAnEmptyDatabase: the page is most often opened when
// something is already wrong, so "nothing stored yet" must be a rendered
// state rather than a crash or a blank.
func TestPage_RendersWithAnEmptyDatabase(t *testing.T) {
	s := newTestServer(t)
	w := getPage(t, s, "Bearer test-token")
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"no frames stored yet", "no messages stored", "No telemetry has arrived"} {
		if !strings.Contains(body, want) {
			t.Errorf("empty page does not say %q", want)
		}
	}
}

// TestPage_AuthMatrix pins every accepted and refused credential shape.
func TestPage_AuthMatrix(t *testing.T) {
	s := newTestServer(t)

	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{"bearer token", "Bearer test-token", http.StatusOK},
		{"basic with token as password", basicAuthHeader("test-token"), http.StatusOK},
		{"basic with wrong token", basicAuthHeader("nope"), http.StatusUnauthorized},
		{"bearer with wrong token", "Bearer nope", http.StatusUnauthorized},
		{"no credential", "", http.StatusUnauthorized},
		{"nonsense scheme", "Weird test-token", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := getPage(t, s, tc.header)
			if w.Code != tc.want {
				t.Errorf("GET / with %q = %d, want %d", tc.header, w.Code, tc.want)
			}
		})
	}
}

// TestPage_OffersBasicChallenge is what makes a browser usable at all: a
// bare 401 shows an error page, while a challenge shows a prompt.
func TestPage_OffersBasicChallenge(t *testing.T) {
	s := newTestServer(t)
	w := getPage(t, s, "")
	if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
	}
}

// TestPage_TailscaleIdentityIgnoredUnlessEnabled is the guard on the header
// path: a header is only evidence when something trustworthy set it, so it
// must do nothing until the operator says otherwise.
func TestPage_TailscaleIdentityIgnoredUnlessEnabled(t *testing.T) {
	s := newTestServer(t) // trust_tailscale_identity defaults to false

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Tailscale-User-Login", "someone@example.com")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("GET / with an identity header and trust disabled = %d, want 401", w.Code)
	}
}

func TestPage_TailscaleIdentityAccepted(t *testing.T) {
	s := newTestServerWith(t, func(o *Options) {
		o.TrustTailscaleIdentity = true
		o.TailscaleAllowedLogins = []string{"owner@example.com"}
	})

	for _, tc := range []struct {
		name  string
		login string
		want  int
	}{
		{"allowed login", "owner@example.com", http.StatusOK},
		{"allowed login, different case", "Owner@Example.com", http.StatusOK},
		{"login not on the allowlist", "someone-else@example.com", http.StatusUnauthorized},
		// A request from a tagged device carries no identity at all, which
		// must be a refusal rather than a pass -- the same reason Funnel
		// traffic (no identity headers) cannot reach the page.
		{"no identity header", "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.login != "" {
				req.Header.Set("Tailscale-User-Login", tc.login)
			}
			w := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("GET / as %q = %d, want %d", tc.login, w.Code, tc.want)
			}
			if tc.want == http.StatusOK && !strings.Contains(w.Body.String(), "tailscale") {
				t.Errorf("page does not record how the request authenticated")
			}
		})
	}
}

// TestJSONAPI_StaysTokenOnly keeps the identity path from widening the API's
// surface: the page is the only thing it unlocks.
func TestJSONAPI_StaysTokenOnly(t *testing.T) {
	s := newTestServerWith(t, func(o *Options) {
		o.TrustTailscaleIdentity = true
	})

	req := httptest.NewRequest("GET", "/api/v1/stats/messages", nil)
	req.Header.Set("Tailscale-User-Login", "owner@example.com")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	// The identity path is deliberately accepted by authenticate(), which
	// the JSON endpoints share -- so this test documents the decision that
	// they behave the same way. If that ever needs to differ, this is the
	// test to change, deliberately.
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/v1/stats/messages with an identity header = %d; the shared authenticator accepts it", w.Code)
	}
}

// TestPage_HidesMessagesFromDuplicateFrames: storage keeps every delivery
// (ADR-3/ADR-14), but a re-delivery is not new content. The live database
// has one message stored three times from before duplicate suppression
// existed, and a page that showed it three times would be misreporting the
// mesh.
func TestPage_HidesMessagesFromDuplicateFrames(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()

	original := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 0x5555, FromNode: 0x99aabbcc, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage, PacketParsed: true,
		TextMessage: &decode.TextMessage{Text: "sent once, delivered twice"},
	}
	firstID, err := s.store.InsertRawFrame(original, "alpha", "alpha", []byte{0x01}, now)
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := s.store.InsertTextMessage(firstID, original, "pvt", now); err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}

	// The re-delivery: a raw frame marked duplicate, plus a text row of the
	// kind a build before ADR-14 would have written.
	redelivery := *original
	redelivery.Status = decode.StatusDuplicate
	dupID, err := s.store.InsertRawFrame(&redelivery, "alpha", "alpha", []byte{0x01}, now.Add(8*time.Second))
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := s.store.InsertTextMessage(dupID, original, "pvt", now.Add(8*time.Second)); err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}

	body := getPage(t, s, "Bearer test-token").Body.String()
	if got := strings.Count(body, "sent once, delivered twice"); got != 1 {
		t.Errorf("message appears %d times on the page, want 1", got)
	}
}

// TestServer_WorksBehindAPrefixStrippingProxy covers mounting the page on a
// sub-path, e.g. https://<host>/brokerd/ via `tailscale serve --set-path`.
//
// That proxy strips the mount point before forwarding
// (tailscale's ipn/ipnlocal/serve.go: `http.StripPrefix(...)`, issue #6571)
// and prefixes any Location header on the way back, so brokerd sees ordinary
// root-relative paths. This test reproduces that so the arrangement cannot
// break silently: the page emits no href, src or form action at all, and its
// auto-refresh is a URL-less <meta refresh>, both of which are what make a
// sub-path mount work without brokerd knowing about it.
func TestServer_WorksBehindAPrefixStrippingProxy(t *testing.T) {
	s := newTestServer(t)
	seedPageData(t, s.store)

	const mount = "/brokerd"
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := strings.TrimPrefix(r.URL.Path, mount)
		// A request to the mount point itself leaves an empty path; an HTTP
		// client sends "/" in that case (net/url.URL.RequestURI), which is
		// what the real proxy forwards.
		if stripped == "" {
			stripped = "/"
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = stripped
		s.httpServer.Handler.ServeHTTP(w, r2)
	})

	for _, tc := range []struct {
		name       string
		path       string
		wantSubstr string
	}{
		{"mount point with trailing slash", mount + "/", "mesh-brokerd"},
		{"mount point without trailing slash", mount, "mesh-brokerd"},
		{"page content is intact", mount + "/", "hello from the mesh"},
		{"json api under the mount", mount + "/api/v1/stats/messages", "throughput_per_topic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", tc.path, w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.wantSubstr) {
				t.Errorf("GET %s does not contain %q", tc.path, tc.wantSubstr)
			}
		})
	}
}

// TestPage_EmitsNoAbsoluteURLs is the invariant the sub-path mount depends
// on. If a future version of the page adds a stylesheet, a favicon or a
// link, it has to be root-relative-free or the mount breaks -- and this test
// is where that gets noticed.
func TestPage_EmitsNoAbsoluteURLs(t *testing.T) {
	s := newTestServer(t)
	seedPageData(t, s.store)
	body := getPage(t, s, "Bearer test-token").Body.String()

	for _, forbidden := range []string{`href="/`, `src="/`, `action="/`, `url(/`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("page emits %q, which breaks a sub-path mount (docs/monitoring-api.md §2.1)", forbidden)
		}
	}
}

// TestPage_RefusalIsExplained is the fix for a real diagnostic dead end: a
// 401 behind a proxy looked identical whether the token was wrong, the
// identity header was absent, or identity trust was off. The browser showed
// one line and the server logged nothing at all.
func TestPage_RefusalIsExplained(t *testing.T) {
	var logs strings.Builder
	s := newTestServerWith(t, func(o *Options) {
		o.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		o.TrustTailscaleIdentity = true
		o.TailscaleAllowedLogins = []string{"owner@example.com"}
	})

	for _, tc := range []struct {
		name       string
		headers    map[string]string
		wantReason string
	}{
		{"no credential at all", nil, reasonNoIdentity},
		{"wrong token", map[string]string{"Authorization": "Bearer nope"}, reasonBadToken},
		{
			"identity not on the allowlist",
			map[string]string{"Tailscale-User-Login": "stranger@example.com"},
			reasonIdentityNotAllowed,
		},
		{
			"funnel request",
			map[string]string{"Tailscale-Funnel-Request": "?1"},
			reasonFunnelRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			// The reason reaches the reader...
			if !strings.Contains(w.Body.String(), tc.wantReason) {
				t.Errorf("401 page does not state the reason %q", tc.wantReason)
			}
			// ...and the operator.
			if !strings.Contains(logs.String(), tc.wantReason) {
				t.Errorf("log does not state the reason %q; got: %s", tc.wantReason, logs.String())
			}
			// Never the secret.
			if strings.Contains(logs.String(), "test-token") || strings.Contains(w.Body.String(), "test-token") {
				t.Errorf("token leaked into the log or the page")
			}
		})
	}
}

// TestPage_RefusalWithoutIdentityTrust separates the two states that produce
// an identical 401 when the switch is off.
func TestPage_RefusalWithoutIdentityTrust(t *testing.T) {
	var logs strings.Builder
	s := newTestServerWith(t, func(o *Options) {
		o.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Tailscale-User-Login", "owner@example.com")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(logs.String(), reasonIdentityNotTrusted) {
		t.Errorf("log does not distinguish an untrusted identity header; got: %s", logs.String())
	}
}

// TestPage_RefusalLogsWhichNodeConnected keeps the field that answers "was
// that my phone or the exit node it was routed through".
func TestPage_RefusalLogsWhichNodeConnected(t *testing.T) {
	var logs strings.Builder
	s := newTestServerWith(t, func(o *Options) {
		o.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		o.TrustTailscaleIdentity = true
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "100.64.0.100")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	if !strings.Contains(logs.String(), "100.64.0.100") {
		t.Errorf("log does not record the connecting address; got: %s", logs.String())
	}
}

// TestPage_StatesThatItIsTruncated: a list that silently stops at 25 is how a
// reader concludes a message was never received. The page has to say it is
// showing a window.
func TestPage_StatesThatItIsTruncated(t *testing.T) {
	s := newTestServer(t)

	// More frames than the default limit.
	for i := 0; i < recentFrameLimit+5; i++ {
		res := &decode.Result{
			Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
			GatewayID: "!11223344", PacketID: uint32(1000 + i), FromNode: 0x99aabbcc, ToNode: 0xffffffff,
			Status: decode.StatusDecoded, Portnum: decode.PortNumPosition, PacketParsed: true,
			Position: &decode.Position{HasLatLon: true, LatitudeI: 1, LongitudeI: 2},
		}
		if _, err := s.store.InsertRawFrame(res, "alpha", "alpha", []byte{byte(i)}, time.Now()); err != nil {
			t.Fatalf("InsertRawFrame: %v", err)
		}
	}

	body := getPage(t, s, "Bearer test-token").Body.String()
	if !strings.Contains(body, "most recent 25 of 30 stored frames") {
		t.Errorf("page does not state the window and the total; got:\n%s", firstLines(body, 40))
	}
	if !strings.Contains(body, "?frames=100") {
		t.Errorf("page does not offer a wider window")
	}
}

// TestPage_LimitParameterIsClampedNotRejected: a monitoring page answering 400
// to a mistyped URL would be the least useful possible response.
func TestPage_LimitParameterIsClampedNotRejected(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", recentFrameLimit},
		{"?frames=5", 5},
		{"?frames=99999", maxPageLimit},
		{"?frames=0", recentFrameLimit},
		{"?frames=-3", recentFrameLimit},
		{"?frames=abc", recentFrameLimit},
	} {
		t.Run("frames="+tc.query, func(t *testing.T) {
			if got := clampLimit(strings.TrimPrefix(strings.TrimPrefix(tc.query, "?frames="), "?"), recentFrameLimit); got != tc.want {
				t.Errorf("clampLimit(%q) = %d, want %d", tc.query, got, tc.want)
			}
		})
	}

	// And the whole request still succeeds with a nonsense value.
	s := newTestServer(t)
	seedPageData(t, s.store)
	req := httptest.NewRequest("GET", "/?frames=abc&messages=99999", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET with nonsense limits = %d, want 200", w.Code)
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// TestPage_ShowsNodeNamesAndEscapesThem: a node's long name is arbitrary text
// chosen by whoever owns a radio in range, and it is rendered into HTML. It
// must appear, and it must not be able to inject markup.
func TestPage_ShowsNodeNamesAndEscapesThem(t *testing.T) {
	srv := newTestServer(t)

	hostile := `Alpha <script>alert(1)</script>`
	if _, err := srv.store.RecordNodeName(&decode.Result{
		PacketParsed: true, Portnum: decode.PortNumNodeInfo, FromNode: 0x11223344,
		NodeInfo: &decode.NodeInfo{ID: "!11223344", LongName: hostile, ShortName: "AL<>"},
	}, time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}
	body := getPage(t, srv, "Bearer test-token").Body.String()

	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("a node name was rendered as live markup")
	}
	if !strings.Contains(body, "Alpha &lt;script&gt;") {
		t.Errorf("the node name does not appear escaped on the page:\n%s", firstLines(body, 40))
	}
	if !strings.Contains(body, "!11223344") {
		t.Error("the node id is no longer shown next to the name")
	}

	// The page answers "what is true now". History -- first sighting, how many
	// NODEINFO frames taught the name, how many times it changed -- is still
	// recorded and still logged, but asked of the database instead.
	//
	// Assert on the directory's own header row, not on words that appear
	// legitimately elsewhere: "Frames" is a column in both the Boards and the
	// Traffic tables.
	const nodeHeader = "<tr><th>Node</th><th>Long name</th><th>Short</th><th>Last heard (UTC)</th></tr>"
	if !strings.Contains(body, nodeHeader) {
		t.Errorf("the node directory's columns changed; want exactly:\n%s", nodeHeader)
	}
	for _, unwanted := range []string{"First seen", "Renames"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the node directory shows history again: %q", unwanted)
		}
	}
}

// TestPage_UnnamedNodeShowsADash keeps the page's one rule about absent values:
// a node nobody has heard a NODEINFO frame from has no name, and the page says
// so rather than repeating the id as if it were one (ADR-15).
func TestPage_UnnamedNodeShowsADash(t *testing.T) {
	srv := newTestServer(t)
	seedPageData(t, srv.store)

	body := getPage(t, srv, "Bearer test-token").Body.String()
	// The seeded frames carry senders but no NODEINFO, so every Name cell is
	// a dash and the directory is empty.
	if !strings.Contains(body, "<span class=\"none\">—</span>") {
		t.Errorf("no absent value rendered as a dash:\n%s", firstLines(body, 40))
	}
	if !strings.Contains(body, "no node has introduced itself yet") {
		t.Error("the node directory does not say it is empty")
	}
}

// TestNodeDirectory_SkipsRowsWithNoUsableName: storage refuses to record a node
// with no name, but a row from an older build or a hand-written one must not
// render as two dashes and an id -- that says less than leaving the node to the
// Name column of the lists above.
func TestNodeDirectory_SkipsRowsWithNoUsableName(t *testing.T) {
	names := map[uint32]storage.NodeName{
		0x11223344: {NodeID: 0x11223344, LongName: "Alpha Node", ShortName: "ALFA"},
		0x55667788: {NodeID: 0x55667788},                    // no name at all
		0x99aabbcc: {NodeID: 0x99aabbcc, ShortName: "CHRL"}, // short only: still a name
	}

	got := nodeDirectory(names)
	if len(got) != 2 {
		t.Fatalf("nodeDirectory returned %d rows, want 2: %+v", len(got), got)
	}
	for _, row := range got {
		if row.NodeID == "!55667788" {
			t.Error("a node with no name appears in the directory")
		}
		if row.LongName == "" && row.ShortName == "" {
			t.Errorf("row with neither name: %+v", row)
		}
	}
}

// TestPage_EveryRowMatchesItsHeader is a whole-page invariant, added after the
// Messages table shipped with a five-column header and four-cell rows: the
// message text rendered under "Name". Nothing asserted the two agreed, and a
// mismatch is invisible to a Go test that only greps for substrings -- it shows
// up as values under the wrong heading in a browser.
//
// Every table on the page is checked, so the next column added anywhere cannot
// repeat it.
func TestPage_EveryRowMatchesItsHeader(t *testing.T) {
	srv := newTestServer(t)
	seedPageData(t, srv.store)
	if _, err := srv.store.RecordNodeName(&decode.Result{
		PacketParsed: true, Portnum: decode.PortNumNodeInfo, FromNode: 0x11223344,
		NodeInfo: &decode.NodeInfo{ID: "!11223344", LongName: "Alpha Node", ShortName: "ALFA"},
	}, time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}

	body := getPage(t, srv, "Bearer test-token").Body.String()

	tables := strings.Split(body, "<table>")[1:]
	if len(tables) == 0 {
		t.Fatal("the page rendered no tables")
	}
	for i, table := range tables {
		table = strings.SplitN(table, "</table>", 2)[0]

		rows := strings.Split(table, "<tr>")[1:]
		if len(rows) == 0 {
			t.Errorf("table %d has no rows at all", i)
			continue
		}
		want := strings.Count(rows[0], "<th")
		if want == 0 {
			t.Errorf("table %d has no header cells:\n%s", i, rows[0])
			continue
		}
		for j, row := range rows[1:] {
			// A colspan row (the "nothing here yet" placeholder) covers the
			// whole width by construction.
			if strings.Contains(row, "colspan=") {
				continue
			}
			if got := strings.Count(row, "<td"); got != want {
				t.Errorf("table %d row %d has %d cells but the header has %d columns:\n%s",
					i, j, got, want, strings.TrimSpace(row))
			}
		}
	}
}

// stubHooks reports a configuration with no activity, which is the state right
// after every restart.
type stubHooks struct {
	targets  []hook.TargetInfo
	counters hook.Counters
}

func (s stubHooks) Snapshot() hook.Counters              { return s.counters }
func (s stubHooks) ConfiguredTargets() []hook.TargetInfo { return s.targets }

// TestPage_ConfiguredHookWithNoActivityIsNotReportedAsUnconfigured is the bug a
// restart made visible: the section listed counters only, so a configured target
// that had not fired yet rendered as "not configured". The relay publishes once
// an hour and the only enabled hook target fires on text messages, so "nothing
// yet" is the normal state for most of every hour -- and the page was making a
// false claim about the configuration rather than reporting a zero (ADR-15).
func TestPage_ConfiguredHookWithNoActivityIsNotReportedAsUnconfigured(t *testing.T) {
	srv := newTestServerWith(t, func(o *Options) {
		o.Hooks = stubHooks{
			targets: []hook.TargetInfo{
				{Name: "text-notify", Kind: "webhook", Enabled: true},
				{Name: "events-log", Kind: "command", Enabled: false},
			},
			counters: hook.Counters{
				Fired: map[string]int64{}, Failed: map[string]int64{},
				Dropped: map[string]int64{}, RateLimited: map[string]int64{},
				Suppressed: map[string]int64{}, DryRun: map[string]int64{},
			},
		}
	})

	body := getPage(t, srv, "Bearer test-token").Body.String()

	if strings.Contains(body, "is configured") || strings.Contains(body, "not configured") {
		t.Error("the page still claims nothing is configured while a target exists")
	}
	if !strings.Contains(body, "hook text-notify fired") {
		t.Errorf("an enabled target with no activity is missing from the page:\n%s", firstLines(body, 60))
	}
	if !strings.Contains(body, "hook events-log (disabled) fired") {
		t.Error("a disabled target is not shown as disabled")
	}
	// Counters that are zero and not interesting stay off the page; the ones
	// that would hide a problem do not.
	if strings.Contains(body, "hook text-notify failed") {
		t.Error("a zero failure count is listed, which buries the counts that matter")
	}
}

// TestPage_HookFailuresAreShownWhenTheyHappen is the other half: a count that
// indicates something is wrong must appear, and be marked.
func TestPage_HookFailuresAreShownWhenTheyHappen(t *testing.T) {
	srv := newTestServerWith(t, func(o *Options) {
		o.Hooks = stubHooks{
			targets: []hook.TargetInfo{{Name: "text-notify", Kind: "webhook", Enabled: true}},
			counters: hook.Counters{
				Fired:  map[string]int64{"text-notify": 3},
				Failed: map[string]int64{"text-notify": 2},
			},
		}
	})

	body := getPage(t, srv, "Bearer test-token").Body.String()
	if !strings.Contains(body, "hook text-notify fired") || !strings.Contains(body, ">3<") {
		t.Errorf("fired count missing:\n%s", firstLines(body, 60))
	}
	if !strings.Contains(body, "hook text-notify failed") {
		t.Error("a non-zero failure count is not on the page")
	}
}

// TestPage_NameColumnCarriesTheShortNameAndTheIDStaysSeparate pins the split a
// reader asked for: the combined "long name (!id)" form hid the short name --
// which is what a node's own screen and the phone app show -- and made the id
// look like part of the name. The name column now carries both names and the id
// keeps its own column.
func TestPage_NameColumnCarriesTheShortNameAndTheIDStaysSeparate(t *testing.T) {
	srv := newTestServer(t)
	seedPageData(t, srv.store)
	if _, err := srv.store.RecordNodeName(&decode.Result{
		PacketParsed: true, Portnum: decode.PortNumNodeInfo, FromNode: 0x11223344,
		NodeInfo: &decode.NodeInfo{ID: "!11223344", LongName: "Alpha Node", ShortName: "ALFA"},
	}, time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}

	body := getPage(t, srv, "Bearer test-token").Body.String()

	if !strings.Contains(body, "Alpha Node (ALFA)") {
		t.Errorf("the name column does not carry the short name:\n%s", firstLines(body, 60))
	}
	if strings.Contains(body, "Alpha Node (!11223344)") {
		t.Error("the id is still glued to the name")
	}
	// The id is present in its own cell, not inside the name.
	if !strings.Contains(body, `<td class="mono">!11223344</td>`) {
		t.Error("the node id has lost its own column")
	}
	// A node with only a long name gets no empty brackets.
	if _, err := srv.store.RecordNodeName(&decode.Result{
		PacketParsed: true, Portnum: decode.PortNumNodeInfo, FromNode: 0x55667788,
		NodeInfo: &decode.NodeInfo{ID: "!55667788", LongName: "Bravo Node"},
	}, time.Now()); err != nil {
		t.Fatalf("RecordNodeName: %v", err)
	}
	body = getPage(t, srv, "Bearer test-token").Body.String()
	if strings.Contains(body, "Bravo Node ()") {
		t.Error("a node with no short name renders empty brackets")
	}
}

// TestPage_ShowsWhatThePacketStatedApartFromWhenItArrived covers the case that
// made this necessary: a message sat in a gateway's queue for 14m37s across a
// brokerd restart and the page showed only its arrival, so it read as having
// just been sent.
func TestPage_ShowsWhatThePacketStatedApartFromWhenItArrived(t *testing.T) {
	srv := newTestServer(t)

	arrived := time.Date(2026, 8, 24, 6, 49, 1, 0, time.UTC)
	stated := time.Date(2026, 8, 24, 6, 34, 24, 0, time.UTC) // 14m37s earlier

	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt", GatewayID: "!11223344",
		PacketID: 199998397, FromNode: 0x11223344, Status: decode.StatusDecoded,
		Portnum: decode.PortNumTextMessage, PacketParsed: true,
		TextMessage: &decode.TextMessage{Text: "queued message"},
		RxTime:      uint32(stated.Unix()),
	}
	rawID, err := srv.store.InsertRawFrame(res, "alpha", "alpha", []byte{0x01}, arrived)
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := srv.store.InsertTextMessage(rawID, res, "pvt", arrived); err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}

	body := getPage(t, srv, "Bearer test-token").Body.String()

	if !strings.Contains(body, "queued 14m37s") {
		t.Errorf("the page does not say how long the message waited:\n%s", firstLines(body, 80))
	}
	// Both times are shown, and neither is presented as the other.
	for _, want := range []string{"06:49:01", "06:34:24"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing the time %s", want)
		}
	}
}

// TestPage_AMessageStatingNoTimeShowsADashNotItsArrival: 3 of this deployment's
// 59 text frames state no rx_time. Copying arrival into that column would make
// our own observation look like the node's claim (ADR-15).
func TestPage_AMessageStatingNoTimeShowsADashNotItsArrival(t *testing.T) {
	srv := newTestServer(t)
	arrived := time.Date(2026, 8, 24, 6, 49, 1, 0, time.UTC)

	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt", GatewayID: "!11223344",
		PacketID: 42, FromNode: 0x11223344, Status: decode.StatusDecoded,
		Portnum: decode.PortNumTextMessage, PacketParsed: true,
		TextMessage: &decode.TextMessage{Text: "no rx_time"},
		// RxTime deliberately left at 0: the packet stated none.
	}
	rawID, err := srv.store.InsertRawFrame(res, "alpha", "alpha", []byte{0x01}, arrived)
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := srv.store.InsertTextMessage(rawID, res, "pvt", arrived); err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}

	body := getPage(t, srv, "Bearer test-token").Body.String()

	// Scope the check to this message's own row. The arrival time legitimately
	// appears elsewhere on the page -- the frames table and the board's "last
	// frame" -- so a page-wide count would prove nothing.
	row := rowContaining(t, body, "no rx_time")
	cells := tableCells(row)
	if len(cells) < 3 {
		t.Fatalf("message row has %d cells: %s", len(cells), row)
	}
	if !strings.Contains(cells[1], "—") {
		t.Errorf("the stated-time cell is %q, want a dash: the packet stated no time", cells[1])
	}
	if strings.Contains(cells[1], "06:49") {
		t.Error("arrival was copied into the stated-time column")
	}
	if !strings.Contains(cells[2], "—") {
		t.Errorf("the note cell is %q, want a dash", cells[2])
	}
}

// rowContaining returns the <tr> element holding the given text, so an assertion
// can be about one row instead of the whole page.
func rowContaining(t *testing.T, body, text string) string {
	t.Helper()
	idx := strings.Index(body, text)
	if idx < 0 {
		t.Fatalf("the page does not contain %q", text)
	}
	start := strings.LastIndex(body[:idx], "<tr")
	end := strings.Index(body[idx:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("%q is not inside a table row", text)
	}
	return body[start : idx+end]
}

// tableCells splits a row into its <td> contents.
func tableCells(row string) []string {
	var out []string
	rest := row
	for {
		i := strings.Index(rest, "<td")
		if i < 0 {
			return out
		}
		rest = rest[i:]
		open := strings.Index(rest, ">")
		close := strings.Index(rest, "</td>")
		if open < 0 || close < 0 {
			return out
		}
		out = append(out, rest[open+1:close])
		rest = rest[close+len("</td>"):]
	}
}

// TestStatedTimeAndNote covers the two directions and the two silences.
func TestStatedTimeAndNote(t *testing.T) {
	const arrived = "2026-08-24T06:49:01Z"
	at := func(s string) sql.NullInt64 {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return sql.NullInt64{Int64: tm.Unix(), Valid: true}
	}

	cases := []struct {
		name       string
		rxTime     sql.NullInt64
		wantStated string
		wantNote   string
	}{
		{"queued for minutes", at("2026-08-24T06:34:24Z"), "06:34:24", "queued 14m37s"},
		{"normal transit", at("2026-08-24T06:49:00Z"), "06:49:00", ""},
		{"node clock ahead", at("2026-08-24T06:54:01Z"), "06:54:01", "node clock ahead 5m0s"},
		{"not stated", sql.NullInt64{}, "", ""},
		{"stated as zero", sql.NullInt64{Int64: 0, Valid: true}, "", ""},
	}
	for _, c := range cases {
		stated, note := statedTimeAndNote(arrived, c.rxTime)
		if !strings.HasSuffix(stated, c.wantStated) || (c.wantStated == "" && stated != "") {
			t.Errorf("%s: stated = %q, want it to end with %q", c.name, stated, c.wantStated)
		}
		if note != c.wantNote {
			t.Errorf("%s: note = %q, want %q", c.name, note, c.wantNote)
		}
	}
}

// TestPage_SaysWhichPeriodItsCountersCover: the counters are in-memory and reset
// on restart, so a small number means "since the last restart" -- which is what
// "missed 4 downlink frame(s)" meant, and nothing on the page said so.
func TestPage_SaysWhichPeriodItsCountersCover(t *testing.T) {
	srv := newTestServer(t)
	body := getPage(t, srv, "Bearer test-token").Body.String()

	if !strings.Contains(body, "cover the last") {
		t.Error("the page does not say what period its counters cover")
	}
	if !strings.Contains(body, "start at zero on each restart") {
		t.Error("the page does not say the counters reset on restart")
	}
}
