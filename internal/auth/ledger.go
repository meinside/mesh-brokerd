package auth

import (
	mauth "github.com/mochi-mqtt/server/v2/hooks/auth"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// BuildLedger constructs the mochi-mqtt auth.Ledger used purely for
// ACL enforcement (docs/security.md §3's "Least-privilege ACL" row) —
// its own OnConnectAuthenticate is never relied on (Ledger compares
// passwords in plaintext, which is exactly why Hook in this package
// exists instead). Every board gets ReadWrite access to its own
// configured acl_filters; a global deny-all rule (matching
// docs/security.md §3's example ACL) rejects everything else,
// including mochi-mqtt's own $SYS tree.
func BuildLedger(boards []config.Board) *mauth.Ledger {
	users := make(mauth.Users, len(boards))
	for _, b := range boards {
		filters := make(mauth.Filters, len(b.ACLFilters))
		for _, f := range b.ACLFilters {
			filters[mauth.RString(f)] = mauth.ReadWrite
		}
		users[b.Username] = mauth.UserRule{
			Username: mauth.RString(b.Username),
			ACL:      filters,
		}
	}

	return &mauth.Ledger{
		Users: users,
		ACL: mauth.ACLRules{
			{Filters: mauth.Filters{"#": mauth.Deny}},
		},
	}
}
