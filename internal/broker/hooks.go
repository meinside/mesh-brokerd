package broker

import "github.com/meinside/mesh-brokerd/internal/hook"

// HookDispatcher is the part of internal/hook the broker needs. An
// interface rather than the concrete type so broker tests can observe what
// would be dispatched without starting a dispatcher, and so a nil
// dispatcher (hooks not configured) stays a plain nil check.
type HookDispatcher interface {
	// Dispatch must not block: internal/hook.Dispatcher queues with a
	// bounded queue and drops its oldest entry when full (ADR-3).
	Dispatch(e hook.Event, rawPayload []byte)
}
