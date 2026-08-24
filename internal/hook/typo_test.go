package hook

import (
	"strings"
	"testing"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// TestValidateTemplates_RejectsAPayloadKeyUsedAsAField covers the mistake the
// payload documentation invites: the payload calls it "board_id", so a template
// gets written as {{.board_id}}. That parses, and Go's text/template only fails
// when it executes -- which is when the first matching event arrives, possibly
// days later, as one log line and a notification nobody receives.
func TestValidateTemplates_RejectsAPayloadKeyUsedAsAField(t *testing.T) {
	cfg := config.EventHooks{Targets: []config.HookTarget{{
		Name: "t", Kind: config.HookKindWebhook, Enabled: true,
		Template: `{{.board_id}} says hello`,
	}}}

	err := ValidateTemplates(cfg)
	if err == nil {
		t.Fatal("a template naming a JSON key instead of a struct field was accepted at startup")
	}
	// The message has to say what to write instead; the error alone
	// ("can't evaluate field board_id") does not.
	if !strings.Contains(err.Error(), "{{.BoardID}}") {
		t.Errorf("error does not point at the right spelling: %v", err)
	}
}

// TestValidateTemplates_AcceptsATemplateThatHandlesAbsentValues: a frame event
// states only what its frame stated, so a template must be validated against an
// event with almost nothing in it as well as a full one.
func TestValidateTemplates_AcceptsATemplateThatHandlesAbsentValues(t *testing.T) {
	for _, tmpl := range []string{
		`{{or .FromName .FromID}}: {{index .Fields "text"}}`,
		`{{.BoardID}} {{if .Portnum}}{{.Portnum}}{{else}}board event{{end}}`,
		`{{json .RxSnr}}`,
		`{{trunc 10 (index .Fields "text")}}`,
		`{{.Reason}}`,
	} {
		cfg := config.EventHooks{Targets: []config.HookTarget{{
			Name: "t", Kind: config.HookKindWebhook, Enabled: true, Template: tmpl,
		}}}
		if err := ValidateTemplates(cfg); err != nil {
			t.Errorf("template %q rejected: %v", tmpl, err)
		}
	}
}
