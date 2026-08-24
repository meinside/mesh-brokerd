package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// render produces the bytes a target receives: the event as JSON, or, when
// the target has a template, the rendered text.
//
// A template gets the same Event the JSON form would carry, *after* the
// opt-in fields have been applied -- so a template cannot reach a message
// body that match.include_text did not allow. text/template rather than
// html/template on purpose: the output goes to a chat message or a
// program's stdin, and HTML escaping would corrupt it.
func (d *Dispatcher) render(t config.HookTarget, e Event, rawPayload []byte) ([]byte, error) {
	e = e.applyMatchOptions(t.Match, rawPayload)
	// Filled here, the moment the payload exists, rather than at delivery:
	// a retry re-sends these exact bytes, so a timestamp that changed between
	// attempts would make one event look like two. It was empty in every
	// payload until a real one was read.
	e.DeliveredAt = d.now().UTC().Format(time.RFC3339)

	if t.Template == "" {
		return e.JSON()
	}

	tmpl, err := parseHookTemplate(t.Name, t.Template)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, e); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}
	return buf.Bytes(), nil
}

// ValidateTemplates parses every configured template once, so a syntax
// error surfaces at startup instead of at the first event
// (docs/event-hooks.md's validation rules).
func ValidateTemplates(cfg config.EventHooks) error {
	for _, t := range cfg.Targets {
		if t.Template == "" {
			continue
		}
		tmpl, err := parseHookTemplate(t.Name, t.Template)
		if err != nil {
			return fmt.Errorf("event_hooks.targets[%q].template: %w", t.Name, err)
		}
		// Parsing is not enough. A template naming a JSON key instead of a
		// struct field -- {{.board_id}} rather than {{.BoardID}}, the obvious
		// mistake to make from reading a payload example -- parses perfectly and
		// fails when the first real event arrives, days later, as one log line
		// and a notification nobody receives.
		//
		// Executing it here against representative events makes that a startup
		// failure. Both a fully populated event and an almost empty one are
		// tried, because a frame states only what it stated (ADR-15) and a
		// template may only break on the absence.
		for _, sample := range sampleEvents() {
			if err := tmpl.Execute(io.Discard, sample); err != nil {
				return fmt.Errorf("event_hooks.targets[%q].template: %w "+
					"(fields are Go names, not the payload's JSON keys: "+
					"{{.BoardID}}, not {{.board_id}} -- docs/event-hooks.md §3.1)", t.Name, err)
			}
		}
	}
	return nil
}

// parseHookTemplate is the only place a hook template is constructed. Having
// two -- one in the renderer, one in the startup validator -- meant the
// validator rejected a template the renderer would have accepted, because only
// one of them registered the function map. Startup validation caught it before
// anything was delivered, which is what it is for, but the drift was the real
// defect.
func parseHookTemplate(name, text string) (*template.Template, error) {
	return template.New(name).Funcs(templateFuncs()).Option("missingkey=zero").Parse(text)
}

// templateFuncs are what a template may call.
//
// `json` exists because a template that builds a JSON body -- which is what a
// chat service's incoming webhook wants -- would otherwise break on the first
// message containing a quote, a backslash or a newline, and a mesh message is
// arbitrary text from whoever is in radio range. text/template does no
// escaping, so the escaping has to be asked for:
//
//	{"body": {{json .Fields.text}}}
//
// `trunc` bounds a field before it reaches a receiver with a length limit.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", fmt.Errorf("json: %w", err)
			}
			return string(b), nil
		},
		"trunc": func(n int, v any) string {
			s := fmt.Sprintf("%v", v)
			if n <= 0 || len(s) <= n {
				return s
			}
			// Cut on a rune boundary so the result stays valid UTF-8; a
			// Korean message truncated mid-rune would arrive as mojibake.
			runes := []rune(s)
			if len(runes) <= n {
				return s
			}
			return string(runes[:n]) + "…"
		},
	}
}

// sampleEvents are the events startup validation renders a template against:
// one stating everything, one stating almost nothing. Between them they cover
// what a real frame event does and does not carry.
func sampleEvents() []Event {
	snr := float32(6)
	rssi := int32(-95)
	hops := uint32(3)
	viaMqtt := false
	bitfield := uint32(1)
	return []Event{
		{
			Event: config.HookEventFrame, DeliveredAt: "2026-01-01T00:00:00Z",
			ReceivedAt: "2026-01-01T00:00:00Z", BoardID: "alpha", GatewayID: "!11223344",
			Topic: "msh/pvt/2/e/pvt/!11223344", Channel: "pvt", PacketID: "0x11223344",
			FromNode: "0x11223344", ToNode: "0xffffffff",
			FromID: "!11223344", FromName: "Sample Node (SMPL)",
			FromLongName: "Sample Node", FromShortName: "SMPL",
			ToID: "!ffffffff", Portnum: "TEXT_MESSAGE_APP",
			RxSnr: &snr, RxRssi: &rssi, HopLimit: &hops, HopStart: &hops,
			ViaMqtt: &viaMqtt, Bitfield: &bitfield,
			Fields: map[string]any{"text": "sample"},
		},
		// A board event: no packet, no portnum, no fields, and a reason.
		{
			Event: config.HookEventBoardDisconnected, DeliveredAt: "2026-01-01T00:00:00Z",
			BoardID: "alpha", Reason: "read timeout",
		},
	}
}
