// Package auth implements brokerd's custom authentication hook
// (docs/security.md §3, ADR-5 in docs/adr.md): bcrypt password
// comparison (mochi-mqtt's own Ledger compares plaintext, confirmed
// from source) plus automatic per-IP banning after repeated failures
// (mochi-mqtt has no such built-in mechanism).
package auth

import (
	"log/slog"
	"net"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"golang.org/x/crypto/bcrypt"
)

// BanInfo describes one currently-active ban
// (docs/monitoring-api.md's /api/v1/stats/auth).
type BanInfo struct {
	IP        string
	ExpiresAt time.Time
}

// Hook is a custom mqtt.Hook implementing only OnConnectAuthenticate
// (ADR-5). It deliberately does not implement OnACLCheck — ACL
// enforcement stays with mochi-mqtt's own auth.Ledger hook
// (docs/security.md §3), registered separately.
type Hook struct {
	mqtt.HookBase

	// boardHashes maps MQTT username -> bcrypt password hash
	// (docs/brokerd-config.md's boards[].password_hash_env, already
	// resolved by internal/config).
	boardHashes map[string]string

	failureThreshold int
	banDuration      time.Duration
	ipAllowlist      map[string]bool

	mu     sync.Mutex
	states map[string]*banState // keyed by remote IP (no port)

	failuresTotal int64
}

type banState struct {
	failureCount int
	bannedUntil  time.Time // zero value means "not banned"
}

// New builds the auth Hook. failureThreshold/banDuration/ipAllowlist
// come from docs/brokerd-config.md's auth.* keys (ADR-5's defaults:
// threshold 5, ban duration 30 minutes).
func New(boardHashes map[string]string, failureThreshold int, banDuration time.Duration, ipAllowlist []string) *Hook {
	allow := make(map[string]bool, len(ipAllowlist))
	for _, ip := range ipAllowlist {
		allow[ip] = true
	}
	h := &Hook{
		boardHashes:      boardHashes,
		failureThreshold: failureThreshold,
		banDuration:      banDuration,
		ipAllowlist:      allow,
		states:           make(map[string]*banState),
	}
	// Default logger so OnConnectAuthenticate's logging never nil-panics
	// before mochi-mqtt calls SetOpts (e.g. in unit tests that construct
	// the Hook directly, docs/protocol-spec.md-style test discipline).
	h.Log = slog.Default()
	return h
}

func (h *Hook) ID() string { return "brokerd-bcrypt-auth" }

func (h *Hook) Provides(b byte) bool {
	return b == mqtt.OnConnectAuthenticate
}

// OnConnectAuthenticate implements bcrypt password comparison plus
// per-IP failure banning (ADR-5). It never logs the password or hash
// (docs/security.md §7), but does log *which* reason a connection was
// rejected for (banned vs. bad credentials) so an operator can tell
// the two apart without exposing secrets.
//
// Accepted connections are logged too. That is not symmetry for its own
// sake: mochi-mqtt's ACL hook is consulted for OnConnectAuthenticate as
// well and declines (it holds no usable password material), logging
// "client failed authentication check" on every *successful* connection.
// Without a success line of our own, the only evidence a board
// authenticated is the absence of a rejection, which is a poor thing to
// diagnose from.
func (h *Hook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	ip := remoteIP(cl.Net.Remote)
	username := string(pk.Connect.Username)

	if !h.ipAllowlist[ip] {
		if banned, until := h.isBanned(ip); banned {
			h.Log.Warn("auth: rejected (IP is currently banned)", "username", username, "remote", ip, "banned_until", until)
			return false
		}
	}

	ok := h.checkPassword(username, pk.Connect.Password)
	if ok {
		h.recordSuccess(ip)
		h.Log.Info("auth: accepted", "username", username, "remote", ip)
		return true
	}

	if !h.ipAllowlist[ip] {
		h.recordFailure(ip)
	}
	h.mu.Lock()
	h.failuresTotal++
	h.mu.Unlock()
	h.Log.Warn("auth: rejected (unknown username or wrong password)", "username", username, "remote", ip)
	return false
}

func (h *Hook) checkPassword(username string, password []byte) bool {
	hash, ok := h.boardHashes[username]
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), password) == nil
}

func (h *Hook) isBanned(ip string) (bool, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.states[ip]
	if !ok || st.bannedUntil.IsZero() {
		return false, time.Time{}
	}
	return time.Now().Before(st.bannedUntil), st.bannedUntil
}

// recordFailure increments ip's failure count and, once the threshold
// is reached, bans it for banDuration. A new failure recorded while
// already banned resets (extends) the ban window (ADR-5: "a new
// failure while banned resets the window").
func (h *Hook) recordFailure(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	st, ok := h.states[ip]
	if !ok {
		st = &banState{}
		h.states[ip] = st
	}
	st.failureCount++

	now := time.Now()
	alreadyBanned := !st.bannedUntil.IsZero() && now.Before(st.bannedUntil)
	if st.failureCount >= h.failureThreshold || alreadyBanned {
		st.bannedUntil = now.Add(h.banDuration)
	}
}

// recordSuccess clears ip's failure state entirely on a correct
// password (ADR-5's in-memory, per-IP counter is reset on success, not
// just on restart).
func (h *Hook) recordSuccess(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.states, ip)
}

// FailuresTotal returns the running total of authentication failures
// since startup (docs/monitoring-api.md's auth_failures_total; ADR-5's
// counter is in-memory only, reset on restart).
func (h *Hook) FailuresTotal() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.failuresTotal
}

// ActiveBans returns every IP currently under an active ban
// (docs/monitoring-api.md's active_bans).
func (h *Hook) ActiveBans() []BanInfo {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	var bans []BanInfo
	for ip, st := range h.states {
		if !st.bannedUntil.IsZero() && now.Before(st.bannedUntil) {
			bans = append(bans, BanInfo{IP: ip, ExpiresAt: st.bannedUntil})
		}
	}
	return bans
}

// remoteIP strips the port from a "host:port" remote address string,
// falling back to the raw string if it doesn't parse (e.g. already
// port-less, or a non-TCP transport).
func remoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
