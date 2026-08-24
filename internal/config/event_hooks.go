package config

import "time"

// EventHooks is the resolved event-hook configuration
// (docs/event-hooks.md). Hooks are notifications, never a delivery
// guarantee: the database is the durable record, and a hook that fails is
// counted and dropped rather than retried forever (ADR-17).
type EventHooks struct {
	Enabled bool

	// DryRun logs what each target would receive without sending or
	// executing anything. Absent means true: the same rollout posture as
	// the outbound relay, since "absent" must never mean "fire for real".
	DryRun bool

	// QueueSize bounds the dispatch queue. A full queue drops its oldest
	// entry and counts it -- the broker's own path is never blocked
	// (ADR-3).
	QueueSize int

	// MaxConcurrent caps simultaneous deliveries and child processes.
	MaxConcurrent int

	Targets []HookTarget
}

// HookKind selects a target's sink.
type HookKind string

const (
	// HookKindWebhook POSTs the event as JSON to an HTTPS endpoint.
	HookKindWebhook HookKind = "webhook"
	// HookKindCommand executes a local program with the event JSON on
	// stdin. See docs/security.md: this is an execution path, so its
	// validation refuses rather than reports.
	HookKindCommand HookKind = "command"
)

// HookTarget is one resolved hook destination.
type HookTarget struct {
	Name    string
	Kind    HookKind
	Enabled bool

	// Webhook fields. URL and Secret are resolved from *_env: a secret is
	// never written in config.json (docs/security.md §7).
	URL    string
	Secret string

	// AllowUnsigned permits a webhook with no signing secret. Many chat
	// services authenticate by the URL itself and have no shared secret to
	// verify with, so demanding one would make them unusable. It must be
	// stated explicitly: an absent secret alone must not silently mean
	// "send anyway".
	AllowUnsigned bool

	// Headers are added to the request after brokerd's own, so a target can
	// satisfy a receiver that requires one (a vendor-specific Accept, for
	// instance).
	// A value of the form ${VAR} is resolved from the environment at load,
	// keeping the rule that secrets live in the environment and never in
	// config.json.
	Headers map[string]string

	// Command fields. Command must be an absolute path; Args are passed as
	// argv, never through a shell, and the event payload arrives on stdin
	// rather than in an argument -- so a message body can never become
	// part of a command line.
	Command string
	Args    []string

	Timeout time.Duration

	// Retries applies to webhooks only. Re-running a command that may
	// already have had an effect is worse than reporting the failure, so a
	// command target is attempted exactly once.
	Retries int

	// DisableAfterFailures auto-disables the target after this many
	// consecutive failures, logging once. 0 disables the feature. State is
	// in memory: a restart re-enables the target.
	DisableAfterFailures int

	// MinInterval rate-limits this target. Events arriving sooner than
	// this after the last delivery are skipped and counted.
	MinInterval time.Duration

	// DedupeWindow suppresses a delivery whose rendered payload is
	// identical to one sent within this window. Storage deliberately does
	// not do this (ADR-14: two identical messages are two messages), but a
	// notification about the same content twice is just noise.
	DedupeWindow time.Duration

	// QuietFrom/QuietTo are minutes-since-local-midnight bounds for a
	// window in which nothing is delivered, or -1 when unset. Local time,
	// deliberately: the operator sets the hours they sleep, not UTC.
	// A window may wrap midnight (QuietFrom > QuietTo).
	QuietFrom int
	QuietTo   int

	// Template renders the event into a single human-readable line for
	// consumers that want text rather than structure. Empty means the
	// payload is sent as JSON.
	Template string

	Match HookMatch
}

// HookMatch decides which events reach a target. An empty list means "no
// filter on this field"; the exception is Events, which defaults to
// frame-only, because a target written for messages should not silently
// start receiving connection events.
type HookMatch struct {
	Events   []string
	Portnums []string
	Channels []string
	Boards   []string

	// IncludeText must be opted into per target: a hook consumer is a
	// third party, and the message body is the one field whose exposure
	// cannot be undone.
	IncludeText bool

	// IncludeRawPayload adds the decrypted Data.payload as base64, for a
	// consumer that decodes portnums itself.
	IncludeRawPayload bool

	// ExcludeOwnBoards drops events whose sending node is one of the
	// configured boards, leaving only traffic that originated elsewhere.
	ExcludeOwnBoards bool
}

// Hook event names. Frame events come from the storage worker; the
// connection events come from the presence hook, which already tracks
// exactly this (docs/architecture.md §8.1).
const (
	HookEventFrame             = "frame"
	HookEventBoardConnected    = "board_connected"
	HookEventBoardDisconnected = "board_disconnected"
)

// HookEventNames lists every event a target may subscribe to.
var HookEventNames = []string{
	HookEventFrame,
	HookEventBoardConnected,
	HookEventBoardDisconnected,
}
