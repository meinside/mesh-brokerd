package monitor

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Authentication for this API has to work for two different callers, and
// they can present the same secret in different ways
// (docs/monitoring-api.md §2):
//
//   - a program (curl, a script, a dashboard) sends
//     `Authorization: Bearer <token>`;
//   - a **browser** cannot set a header by typing a URL, so it may instead
//     send `Authorization: Basic <base64(anything:<token>)>`, which every
//     browser knows how to prompt for. The username is ignored; the token
//     goes in the password field.
//
// A query parameter was rejected: a token in a URL lands in server logs,
// browser history and `Referer` headers, and no amount of documentation
// prevents it from being pasted somewhere.
//
// Optionally, and only when explicitly configured, a request may instead be
// authenticated by an identity header from a Tailscale Serve proxy
// (identityAuth below).
type authResult struct {
	ok bool
	// via records how the request authenticated, for the log line and for
	// the page footer. Never the secret itself.
	via string
	// login is the Tailscale login when that is how it authenticated.
	login string
	// reason explains a refusal, so a 401 leaves evidence instead of a
	// guess. An unexplained 401 behind a proxy is otherwise undiagnosable
	// from either side: the browser shows a page and the server logs
	// nothing: an absent log line is not an absent event.
	reason string
}

// Refusal reasons, all of them distinguishable in the log.
const (
	reasonNoCredential       = "no_credential"
	reasonBadToken           = "bad_token"
	reasonIdentityNotTrusted = "identity_header_present_but_trust_disabled"
	reasonIdentityNotAllowed = "identity_not_on_allowlist"
	reasonNoIdentity         = "no_identity_header"
	reasonFunnelRequest      = "funnel_request"
)

func (s *Server) authenticate(r *http.Request) authResult {
	header := r.Header.Get("Authorization")

	switch {
	case strings.HasPrefix(header, "Bearer "):
		if tokenMatches(strings.TrimPrefix(header, "Bearer "), s.token) {
			return authResult{ok: true, via: "bearer"}
		}
		return authResult{reason: reasonBadToken}

	case strings.HasPrefix(header, "Basic "):
		// The username is deliberately unused: the token is the only
		// secret, and requiring a matching username would invent a second
		// one for no gain.
		_, password, hasColon := r.BasicAuth()
		if hasColon && tokenMatches(password, s.token) {
			return authResult{ok: true, via: "basic"}
		}
		return authResult{reason: reasonBadToken}
	}

	return s.identityAuth(r)
}

// identityAuth accepts a request that carries a Tailscale Serve identity
// header, but only when monitoring.trust_tailscale_identity is on.
//
// Why this is safe *only* under those conditions, from Tailscale's own
// documentation: Serve injects Tailscale-User-Login and strips any copy the
// client supplied, and Funnel — which is public — does not inject it at
// all. The header is therefore trustworthy exactly as long as nothing but
// the local Serve proxy can reach this listener, which is why the default
// listen address is loopback (docs/monitoring-api.md §0) and why binding it
// anywhere else disables this path's premise rather than extending it.
//
// A missing header is always a refusal. That makes the failure mode of
// someone running `tailscale funnel` on this port a locked page rather than
// a public one.
func (s *Server) identityAuth(r *http.Request) authResult {
	login := r.Header.Get("Tailscale-User-Login")

	// A Funnel request is public traffic. Tailscale marks it and injects no
	// identity, so this is both a refusal and the clearest possible evidence
	// that the port was exposed with `funnel` rather than `serve`.
	if r.Header.Get("Tailscale-Funnel-Request") != "" {
		return authResult{reason: reasonFunnelRequest}
	}
	if !s.trustTailscaleIdentity {
		if login != "" {
			return authResult{reason: reasonIdentityNotTrusted}
		}
		return authResult{reason: reasonNoCredential}
	}
	if login == "" {
		// Requests from *tagged* devices carry no identity at all, and
		// neither does traffic Tailscale cannot attribute: a request that
		// reached the listener without passing through the proxy, or one
		// whose source is a tagged node such as an exit node the client was
		// routed through (tailscale's ipn/ipnlocal/serve.go refuses to
		// attribute either).
		return authResult{reason: reasonNoIdentity}
	}
	if len(s.tailscaleAllowedLogins) > 0 && !allowedLogin(login, s.tailscaleAllowedLogins) {
		return authResult{reason: reasonIdentityNotAllowed, login: login}
	}
	return authResult{ok: true, via: "tailscale", login: login}
}

// logRefusal records why a request was refused. The token never appears; the
// login does, because it is the one value that explains an allowlist
// mismatch, and X-Forwarded-For does, because it names which tailnet node
// actually connected -- the difference between a phone and an exit node it
// was routed through.
func (s *Server) logRefusal(r *http.Request, res authResult) {
	s.log.Info("monitoring: request refused",
		"path", r.URL.Path,
		"reason", res.reason,
		"identity", res.login,
		"identity_header_present", r.Header.Get("Tailscale-User-Login") != "",
		"forwarded_for", r.Header.Get("X-Forwarded-For"),
		"trust_tailscale_identity", s.trustTailscaleIdentity,
	)
}

func allowedLogin(login string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, login) {
			return true
		}
	}
	return false
}

// tokenMatches compares in constant time, so a wrong token cannot be
// narrowed down by timing.
func tokenMatches(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// requireAuth guards a JSON endpoint.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := s.authenticate(r)
		if !res.ok {
			s.logRefusal(r, res)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requirePageAuth guards the HTML page. It differs from requireAuth in one
// respect: it offers Basic authentication, so a browser prompts for a
// credential instead of showing a bare 401. Programs are unaffected — they
// already send a header and never see the challenge.
func (s *Server) requirePageAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := s.authenticate(r)
		if !res.ok {
			s.logRefusal(r, res)
			w.Header().Set("WWW-Authenticate", `Basic realm="mesh-brokerd monitoring", charset="UTF-8"`)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			s.writeUnauthorizedPage(w, res)
			return
		}
		next(w, r)
	}
}
