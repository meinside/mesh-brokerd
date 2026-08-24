package config

import "testing"

// TestLoad_RealSampleFile is a smoke test confirming
// config.json.sample itself (the one thing operators actually copy)
// parses cleanly through the real loader end to end.
func TestLoad_RealSampleFile(t *testing.T) {
	t.Setenv("BROKERD_DNS_TOKEN", "x")
	t.Setenv("BROKERD_BOARD_ALPHA_PASSWORD_HASH", "$2a$12$abcdefghijklmnopqrstuv")
	t.Setenv("BROKERD_BOARD_BRAVO_PASSWORD_HASH", "$2a$12$abcdefghijklmnopqrstuv")
	t.Setenv("BROKERD_CHANNEL_PRVTCHN_PSK", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
	t.Setenv("BROKERD_MONITORING_TOKEN", "x")
	t.Setenv("BROKERD_RELAY_PUBLIC_PASSWORD", "large4cats")

	cfg, err := Load("../../config.json.sample")
	if err != nil {
		t.Fatalf("Load(config.json.sample): %v", err)
	}
	if len(cfg.Boards) != 2 || len(cfg.Channels) != 1 {
		t.Fatalf("boards=%d channels=%d, want 2/1", len(cfg.Boards), len(cfg.Channels))
	}
	// The sample ships both hook targets disabled, so copying it can never
	// fire anything; the block must still parse and default dry_run to on.
	if cfg.EventHooks.Enabled {
		t.Error("sample file's event_hooks.enabled should load as false (the safe shipped default)")
	}
	if !cfg.EventHooks.DryRun {
		t.Error("sample file's event_hooks should load with dry_run true")
	}
	if len(cfg.EventHooks.Targets) == 0 {
		t.Error("sample file's event_hooks targets did not parse")
	}
	for _, target := range cfg.EventHooks.Targets {
		if target.Enabled {
			t.Errorf("sample file's event_hooks target %q ships enabled", target.Name)
		}
	}

	if cfg.OutboundRelay.Enabled {
		t.Error("sample file's outbound_relay.enabled should load as false (the safe shipped default)")
	}
	// Counts deliberately not pinned: the sample grew from one rule to one
	// per supported portnum, and a hardcoded number turns documentation
	// improvements into test failures. What matters is that the relay block
	// parses even while disabled, and that it ships in the safe state.
	if len(cfg.OutboundRelay.Targets) == 0 || len(cfg.OutboundRelay.Rules) == 0 {
		t.Errorf("outbound_relay targets=%d rules=%d, want the block parsed even while disabled",
			len(cfg.OutboundRelay.Targets), len(cfg.OutboundRelay.Rules))
	}
	if !cfg.OutboundRelay.DryRunAllRules {
		t.Error("sample file must ship with dry_run_all_rules true: copying it must never publish to a public server")
	}

	// A rule using own_boards_only matches on a board's node_id, so a sample
	// that pairs the two without node_ids would demonstrate a rule that can
	// never fire. Boards carry them; check the pairing holds.
	for _, r := range cfg.OutboundRelay.Rules {
		if r.OriginScope != OriginScopeOwnBoardsOnly {
			continue
		}
		for _, id := range r.Boards {
			var found bool
			for _, b := range cfg.Boards {
				if b.ID == id {
					found = true
					if !b.HasNodeID {
						t.Errorf("rule %q uses own_boards_only but board %q has no node_id, so it could never match", r.ID, id)
					}
				}
			}
			if !found {
				t.Errorf("rule %q lists board %q, which is not in boards[]", r.ID, id)
			}
		}
	}
}
