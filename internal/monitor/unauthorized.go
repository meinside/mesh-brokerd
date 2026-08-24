package monitor

import (
	"html/template"
	"net/http"
)

// unauthorizedTemplate is the body of a 401 on the page route.
//
// The `WWW-Authenticate` header is still sent, so a browser that offers a
// Basic prompt still does. This exists because not every browser does --
// observed in practice behind a Tailscale Serve proxy, where the header
// arrived intact and no prompt appeared -- and a reader who gets no prompt
// otherwise gets one line of text with no way forward.
//
// It states the refusal reason, because the alternatives look identical from
// a browser: a missing credential, a wrong token, an identity header that is
// not trusted, and an identity that is not on the allowlist all render as the
// same blank 401.
var unauthorizedTemplate = template.Must(template.New("401").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>brokerd monitoring — sign in</title>
<style>
:root { color-scheme: light dark; }
body { font: 14px/1.6 system-ui, sans-serif; margin: 0 auto; padding: 1.5rem; max-width: 42rem; }
h1 { font-size: 1.1rem; }
code { font-family: ui-monospace, monospace; font-size: .9em; }
.reason { opacity: .8; }
li { margin: .4rem 0; }
</style>
</head>
<body>
<h1>Not authorized</h1>
<p class="reason">Refused because: <code>{{.Reason}}</code></p>
<p>{{.Explanation}}</p>
<ul>
<li>If a password prompt appeared, use <strong>any username</strong> and the
    monitoring token as the <strong>password</strong>.</li>
<li>If no prompt appeared, your browser did not offer one for this response.
    Reload the page, or open
    <code>https://&lt;user&gt;:&lt;token&gt;@&lt;host&gt;/</code> if your browser
    still supports credentials in a URL.</li>
<li>From a shell:
    <code>curl -u :&lt;token&gt; &lt;url&gt;</code>.</li>
</ul>
<p>Every refusal is logged with its reason on the server
(<code>journalctl -u mesh-brokerd</code>), including whether an identity
header arrived and which address it came from.</p>
</body>
</html>
`))

type unauthorizedData struct {
	Reason      string
	Explanation string
}

// refusalExplanations turns a reason into something actionable. Each one
// names the specific next step, because "unauthorized" on its own sends the
// reader to guess at the wrong layer.
var refusalExplanations = map[string]string{
	reasonNoCredential: "No credential was presented.",
	reasonBadToken:     "The token presented does not match the configured monitoring token.",
	reasonIdentityNotTrusted: "A Tailscale identity header arrived, but " +
		"monitoring.trust_tailscale_identity is off in this deployment's config, " +
		"so the token is required.",
	reasonIdentityNotAllowed: "A Tailscale identity arrived but is not in " +
		"monitoring.tailscale_allowed_logins.",
	reasonNoIdentity: "Identity trust is on, but this request carried no Tailscale " +
		"identity header. Tailscale does not attribute traffic from tagged devices, " +
		"nor traffic that did not pass through the Serve proxy — including a request " +
		"routed through an exit node. Use a user-owned device directly, or the token.",
	reasonFunnelRequest: "This request came in over Tailscale Funnel, which is public " +
		"and carries no identity. The page never accepts Funnel traffic; expose the " +
		"port with `tailscale serve`, not `tailscale funnel`.",
}

func (s *Server) writeUnauthorizedPage(w http.ResponseWriter, res authResult) {
	reason := res.reason
	if reason == "" {
		reason = reasonNoCredential
	}
	explanation := refusalExplanations[reason]
	if explanation == "" {
		explanation = "No credential was accepted."
	}
	// Errors here are unrecoverable: the status and headers are already
	// written, and the client is mid-body.
	_ = unauthorizedTemplate.Execute(w, unauthorizedData{Reason: reason, Explanation: explanation})
}
