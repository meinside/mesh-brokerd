# Selective Outbound Relay

Design for `brokerd`'s narrow, publish-only relay of specific, whitelisted
information to an external MQTT target (v1: the official Meshtastic
public MQTT server), adopted as a scoped exception to full federation
(`docs/architecture.md` §10.2.1, which stays deferred). ADR-12
(`docs/adr.md`) records the decision to build this.

## 1. Design principles

1. **Whitelist, not mirror.** Nothing crosses this boundary by default.
   Every portnum that can be relayed needs its own explicit **rule**; an
   unmatched packet is never forwarded, never logged as "would have
   matched," and never touches the outbound path at all.
2. **Fail-closed eligibility, not `brokerd`-side redaction.** `brokerd`
   never edits/coarsens data to make it safe to forward — it only
   forwards data the *sending board* already chose to make coarse. If a
   board's config changes to broadcast precise data, forwarding stops
   automatically. A **missing/empty position** (no GPS fix, §4) is
   rejected explicitly too — "fail-closed" covers absent data, not only
   overly-precise data.
3. **Publish-only.** `brokerd` never subscribes to the external target.
   Nothing from the public server (or any future target) ever reaches a
   board through this feature — sidesteps §10.2.1's loop-suppression
   problem entirely, by construction.
4. **Opt-in per board, per rule.** A board's data is never eligible for
   any rule unless that board is explicitly listed. Adding a board to
   `brokerd`'s config (`docs/architecture.md` §10.1) never implicitly
   opts it into relay.
5. **Isolated failure domain.** Exactly like storage (ADR-3), a failure
   or slowdown in the outbound relay path must never affect the broker's
   relay of the boards' own private traffic, or the storage write path.

## 2. Board-side prerequisites

Turning this feature on is not purely a `brokerd`-side decision — the
relaying board's own channel config must also be set up correctly.

1. **A real position source must exist.** Neither deployed board has one
   today (`position.gps_mode = NOT_PRESENT`, `position.fixed_position =
   false`, `docs/firmware-config.md` §5) — without a GPS module, a
   phone-shared location, or a manual `fixed_position`, there is no
   `POSITION_APP` packet to act on.
2. **`position_precision` must be set on the `pvt` channel specifically**
   (an integer 0–32, `ChannelSettings.ModuleSettings.position_precision`)
   — not the primary channel, which is never uplinked
   (`docs/firmware-config.md` §7). Only the lowest-indexed secondary
   channel with location sharing enabled gets automatic broadcasts.
3. **Disable location sharing on Channel 0 (primary).** Official
   recommendation independent of this feature; also mitigates a firmware
   caveat where a secondary channel's precision may be
   overridden by the primary's.
4. **The `pvt` precision value and `brokerd`'s eligibility range
   are configured independently and must be kept in sync manually** —
   there is no negotiation between board and `brokerd`.
5. **Configured per node, individually.** The channel itself (name + PSK
   + `uplink_enabled`) is shared once via a QR code/URL, but position
   source, precision, and broadcast interval are each node's own local
   config — enabling this for both boards means steps 1–3 twice,
   independently.
6. **A node that isn't a `pvt` channel member cannot be relayed at all,
   structurally** — it doesn't know the PSK, so it can't construct a
   matching packet in the first place, regardless of LoRa proximity.
7. **A `pvt` member that isn't one of `brokerd`'s own gateway boards**
   (e.g. a battery-powered mobile node, `docs/firmware-config.md` §7) is
   eligible for relay by default too, provided it broadcasts a
   qualifying position **and is within LoRa range of a gateway board**
   (a physical prerequisite, not a setting). This is intentional: the
   real consent signal is a member's own deliberate `position_precision`
   setting, not which account gatewayed the packet — so §3's
   `origin_scope` defaults to `"channel_members"`, covering any `pvt`
   member. The stricter `"own_boards_only"` (§3) exists for an operator
   who invites guests onto the channel without extending this feature to
   them.

Enabling this end-to-end is a two-sided change — the board's own channel
config plus `brokerd`'s `outbound_relay` config (§3) — never something
`brokerd` can switch on unilaterally.

## 3. Rule engine schema (`brokerd-config.md` extension)

```json
{
  "outbound_relay": {
    "enabled": false,
    "dry_run_all_rules": true,
    "targets": [
      {
        "id": "meshtastic-public",
        "address": "mqtt.meshtastic.org:8883",
        "tls_enabled": true,
        "root_topic": "msh/<REGION>",
        "channel_name": "LongFast",
        "psk": "default",
        "username": "meshdev",
        "password_env": "BROKERD_RELAY_PUBLIC_PASSWORD"
      }
    ],
    "rules": [
      {
        "id": "coarse-position",
        "enabled": true,
        "source_portnum": "POSITION_APP",
        "target": "meshtastic-public",
        "origin_scope": "channel_members",
        "boards": ["alpha", "bravo"],
        "identity": "real",
        "eligibility": {
          "min_precision_bits": 10,
          "max_precision_bits": 16
        }
        },
        {
          "id": "own-mapreport",
          "enabled": false,
          "source_portnum": "MAP_REPORT_APP",
          "target": "meshtastic-public",
          "origin_scope": "own_boards_only",
          "boards": ["alpha"],
          "identity": "real"
        }
    ]
  }
}
```

- **`outbound_relay.enabled`** — global kill switch, defaults to `false`.
- **`outbound_relay.dry_run_all_rules`** — see §7. **Applies to every rule**, not to one feature: with it on, no rule publishes anything externally. **Absent means `true`** (suppressed) — the safe setting does not depend on remembering to write it. The pre-rename key `dry_run` is rejected at load rather than ignored.
- **`targets[]`** — v1 ships one target (the official public server), but
  it's a list so a future self-hosted community broker could be added
  without a redesign (still not generic federation). `psk: "default"` is
  a sentinel for Meshtastic's well-known default channel key, never a
  real secret.
- **`rules[].origin_scope`**:
  - `"channel_members"` **(default)**: eligible if uplinked by one of
    the listed boards' gateway accounts, regardless of who originated
    it — relays any `pvt` member's position, not just the gateway
    boards' own (§2 point 7).
  - `"own_boards_only"` (stricter opt-in): eligible only if
    `raw_frames.from_node` matches one of the listed boards' own node
    IDs (`boards[].node_id` in `brokerd-config.md`).
- **`rules[].boards`** — under `"channel_members"`, the gateway-account
  filter; under `"own_boards_only"`, resolved to node IDs instead. Omit
  for "all configured boards" either way.
- **`rules[]`** — each independently `enabled`, with a portnum-specific
  `eligibility` predicate. v1 implements one predicate shape
  (`min_precision_bits`/`max_precision_bits` for `POSITION_APP`); a new
  portnum needs a new predicate shape, not an engine redesign.
- **`identity`** — `"real"` (v1's only implemented option) or
  `"anonymized"` (schema slot reserved, not implemented).

## 4. Processing pipeline

Boards send position updates on their own independent, per-node timer —
not triggered by discovery/ping exchanges, and not bundled with text
messages or any other packet type. With this project's
`position_broadcast_smart_enabled = false` (`docs/firmware-config.md`
§5), each member broadcasts on a fixed interval
(`position_broadcast_secs` — confirmed on a real test board as `3600`
seconds; verify per device rather than assuming the official docs'
"15 minutes if left at 0" figure), regardless of movement, and regardless
of whether it currently has a GPS fix — a no-fix broadcast still goes out
with an empty location. The pipeline below validates that a position
actually has coordinates, not just that its precision tag looks
acceptable.

```
raw_frames row (already decrypted via the board's own private channel PSK)
  -> internal/decode's POSITION_APP decoder (docs/protocol-spec.md §4)
  -> for each enabled rule whose source_portnum matches:
       -> evaluate eligibility:
            1. latitude_i and longitude_i are both present — an
               empty/no-fix broadcast has neither, rejected here first
            2. precision_bits is set and falls within [min,max]
            3. origin_scope's board/node filter matches (§3)
       -> if eligible: hand off to the outbound relay worker (its own
          goroutine + bounded queue, mirroring ADR-3's isolation pattern)
       -> if not eligible: nothing happens; not logged as a near-miss
          (avoids a log of every board's precise-position moments)
  -> outbound relay worker:
       -> construct a new ServiceEnvelope/MeshPacket for the target (§5)
       -> encrypt with the target's PSK (§6)
       -> publish to <root_topic>/2/e/<channel_name>/<gateway_id>
          on the target's MQTT connection (or log-only, if dry_run, §7)
```

### 4.1. Rejecting positions with no real fix

Eligibility rejects a position whose underlying coordinates were zero, in
addition to the precision-range check. This is a separate step because it
cannot be folded into a "does it have a position" test:

Meshtastic truncation masks off the low `32 - precision_bits` and then adds
half a cell, so a zero coordinate does **not** arrive as zero. At 13 bits it
arrives as `0x00040000` on both axes — 0.0262°, in the Gulf of Guinea. The
packet has `HasLatLon = true`, a precision inside the eligible range, and
decodes cleanly. Without this check it is relayed, and a "Null Island" node
appears on public maps.

The test is the exact signature rather than a proximity heuristic: a zero
coordinate at precision `p` is precisely `1<<(31-p)` on both axes. A real
position is only rejected if it lands on that exact point on *both* axes,
which is open ocean.

Where the zero positions come from: a board with `gps_mode = ENABLED` but no
GPS hardware broadcasts them interleaved with its real fixed position
(`docs/firmware-config.md` §15). Fixing the board is the right response —
this check is a guard, not a substitute.

`dry_run` caught this before anything reached the public server, which is
the concrete argument for §7's rollout order.

### 4.2. `root_topic` carries the region, and it is configuration

The public server's topic grammar is `msh/<REGION>/2/e/<CHANNEL>/<NODE>` —
the region is part of the **root topic string**, not a separate protocol
element. The firmware behaves the same way: its default root is
`msh/<REGION>`, and a board with a custom `mqtt.root` (this project uses
`msh/pvt`) publishes to `<root>/2/e/...` with no region inserted at all.

So the region belongs in `targets[].root_topic` and nowhere else. `brokerd`
never derives or infers it: the topic is assembled purely from configuration
(`internal/relay`). `config.json.sample` therefore ships
`"root_topic": "msh/<REGION>"`, a placeholder — this repository holds no
deployment's region.

Because that placeholder would otherwise be published verbatim, loading
**fails** if `root_topic` still contains `<` or `>` while
`outbound_relay.enabled` is true. A nonsense topic on shared public
infrastructure draws no complaint from anything downstream — the broker
accepts whatever the ACL allows — so the check has to be at load time. It is
skipped when the relay is disabled, which is the shape the sample ships in.

**Observed against the live public server** (read-only subscription,
2026-08-19):

| Subscription | Result |
|---|---|
| `msh/#` | **rejected** — the server drops the connection before the subscription completes |
| `msh/US/2/e/LongFast/#` | steady real traffic |
| `msh/KR/2/e/#` | **no traffic in 90 seconds** |

Two things follow. The topic grammar is confirmed from real traffic rather
than documentation alone. And a region with no other participants may simply
have no consumers listening: a map front-end that subscribes per active
region would never see a lone publisher on an otherwise-silent one. That is a
candidate explanation for a published position not appearing on a public map,
independent of packet contents.

## 5. Outbound packet construction

- **Topic**: `<target.root_topic>/2/e/<target.channel_name>/<gateway_id>`
  — the same grammar as `docs/protocol-spec.md` §1.
- **`gateway_id`**: the relaying board's real `!hex` node ID
  (`identity: "real"`, v1's only implemented option).
- **`MeshPacket.channel`**: the channel hash for the target channel
  (`target.channel_name` + the target's PSK), so hash-filtering
  consumers still accept the packet.
- **Payload**: a `Data` message with the source packet's own portnum and
  its **decrypted payload bytes verbatim** (`decode.Result.RawPayload`) —
  relayed as-is, never re-synthesized. This is load-bearing, not stylistic:
  an implementation that rebuilt the payload from the parsed struct dropped
  every field the decoder does not model, including a position's `time`,
  which a public map needs to judge whether the position is current (§11).
- **Optional envelope fields** (`rx_time`, `hop_limit`, `hop_start`,
  `priority`, `relay_node`) are **copied from the source packet**, never
  synthesized, and omitted when the source lacks them — an absent
  `hop_limit` is not the same as `hop_limit = 0`. Real gateway traffic
  always carries several of them; a reduced field set was accepted by the
  broker and ignored by consumers (§11).
- **`NodeinfoApp` is out of scope for v1** — a relayed node shows up as a
  bare node ID, not a name.

## 6. Encryption

The target's `psk: "default"` resolves to Meshtastic's well-known default
channel key (`internal/decode.DefaultChannelPSK`) — confirmed directly
from firmware source (`src/mesh/Channels.h`'s `defaultpsk` constant):
**16 bytes, AES-128**, not AES-256 like this project's own channels
(ADR-11 requires 32 bytes for those). Encryption reuses the same
`internal/decode.CryptCTR` engine the boards' own private channel
decoding uses (`docs/protocol-spec.md` §3) — written generically (key
+ nonce in, plaintext/ciphertext out, symmetric, and accepting any
AES-valid key length rather than assuming 32 bytes) so this feature
adds no new crypto code, only a new caller and a new (public,
non-secret) key constant. The outbound packet's `MeshPacket.channel`
hash (§5) is computed over these same 16 expanded bytes, matching how
the firmware computes the hash for any channel using a short-form PSK.

### 6.1. Target authentication

The target broker's credentials are `targets[].username` and
`targets[].password_env` (`docs/brokerd-config.md`). They are **not optional
for the official public server**.

**Where its credentials come from.** `meshdev` / `large4cats` are the
firmware's own published constants, not anyone's account:

The firmware's `src/mesh/Default.h` defines them as compile-time defaults
(described rather than quoted — ADR-13):

| Default | Value |
| --- | --- |
| MQTT address | `mqtt.meshtastic.org` |
| Username | `meshdev` |
| Password | `large4cats` |

`NodeDB.cpp` copies them into every device's initial configuration, which is
why a board that has never been configured is already pointed at the public
server with working credentials (`docs/firmware-config.md` §11A — the reason
`mqtt.address` must be overwritten *before* MQTT is enabled).

So the password is not a secret. It is still passed by
`password_env` rather than written into `config.json`, so that credentials
always arrive the same way and an operator never has to decide, per target,
whether a given password counts as one. A second target — a private
community broker, say — would carry a real secret, and the rule should not
change shape at that point.

This was missing from the first implementation: `RelayTarget` had no
credential fields and the publisher never called `SetUsername`/
`SetPassword`, so a real publish to the public server would have been
refused at connect. It survived review because **`dry_run` never opens a
connection** — the whole point of the mode is to skip the network, so it
cannot exercise authentication. Anything that only happens on a real
publish needs its own test; `internal/relay.TestPahoPublisher_AppliesTargetCredentials`
covers the wiring without a live broker.

## 7. Safe rollout: `dry_run` mode

Testing against the real official public server on every run would be
inconsiderate use of shared community infrastructure. `dry_run_all_rules: true`
(the default) makes the outbound relay worker do everything **except the
final network publish**: decode, evaluate eligibility, construct the
packet, encrypt it — then log a single structured line (board, rule,
target, topic, byte length) instead of opening a connection. This is the
intended way to validate the feature end-to-end without ever touching
`mqtt.meshtastic.org`. Only flip `dry_run_all_rules: false` deliberately, after a
rule has been reviewed for what it exposes.

Separately: Meshtastic's own docs are inconsistent about whether the
public server is meant for ongoing automated use at all —
mitigated by keeping actual traffic minimal (one rule, one board's worth
of coarse position, default interval), not by anything `dry_run` itself
controls.

## 8. Monitoring

New counters, added to `docs/monitoring-api.md`'s `/api/v1/stats/messages`
response:
- `outbound_relay.dry_run_total` (by rule)
- `outbound_relay.published_total` (by rule) — only increments when
  `dry_run` is `false` and a publish actually succeeded
- `outbound_relay.publish_failures_total` (by rule)

Each outcome also logs one structured line at `INFO`, carrying the same
fields in all three cases (rule, target, topic, byte length): `dry_run`,
`published`, and — at `ERROR` — `publish failed`.

The `published` line was originally missing: `dry_run` logged, failures
logged, and a successful publish only incremented a counter. Because the
counters live in memory, a restart erased the only evidence that anything
had been sent, so after an irreversible disclosure to a public server the
system held no record of it. A publish is the one outcome that cannot be
undone and therefore the one that most needs a durable trace.

No per-message content or coordinates are logged; counts only. A future
audit trail (what was actually sent, when) is a candidate
`storage-schema.md` addition, not yet designed.

## 9. Deliberate limits of v1

What this feature does **not** do, each by choice rather than oversight:

- `identity: "anonymized"` is a reserved schema slot with no
  implementation. Only `"real"` is accepted, so a rule cannot claim to
  anonymise something it does not.
- There is no persistent audit trail of what was relayed — only the
  in-memory counters in §8. A published packet is an irreversible
  disclosure, so this is the gap most worth closing first (§8).
- `NodeinfoApp` relaying carries a bare node ID rather than a name (§10.1);
  whether a name should ever be relayed is left undecided.
- Whether a secondary channel's `position_precision` can be overridden by
  the primary's (`meshtastic/firmware#9800`) is unverified for the firmware
  in use. §2 point 3's mitigation — disabling Channel 0 location sharing —
  is the safe default either way.
- Whether ongoing automated relaying is good-faith use of the public
  server at all is a judgement, not a setting (§7). It is why every rule
  ships disabled.

## 10. Candidate rules beyond position

Position (`POSITION_APP`) is the first rule because it's the minimum
needed for the motivating use case (visibility on meshmap-like public
maps). Other portnums fit the same rule-engine (§3) — each just needs a
new `source_portnum` + its own eligibility predicate, no engine redesign.

### 10.1. `MAP_REPORT_APP` — the only route onto a public map

meshmap.net will not display a node without a name:

Its validity check (`internal/meshtastic/node.go` in the
`brianshea2/meshmap.net` repository — AGPL-3.0, so described here rather than
quoted) rejects a node unless **all three** hold: it has been seen by at least
one uplinking gateway, its long name is a non-empty string, and its latitude
and longitude are not both zero.

`LongName` comes from `NODEINFO_APP` or `MAP_REPORT_APP` only, and of those
just `MAP_REPORT_APP` reaches `brokerd` (§10.2 — a NodeInfo *broadcast* goes
out on the primary channel, which the gateways never uplink). It also carries
name and position in one packet, satisfying all three conditions.

So `coarse-position` alone gets a node onto the public server and into other
nodes' NodeDBs, but **never onto the map**.

Properties a relay has to reproduce, confirmed from firmware source:

- it is published on `<root>/2/map/`, with no channel segment in the topic;
- it is the MeshPacket's **`decoded` (plaintext) variant** — there is nothing
  to decrypt and no channel to look a PSK up by, so any implementation that
  requires either will silently drop it;
- its precision comes from `map_report_settings.position_precision`, not from
  the channel's.

It remains **self-report only** — a node needs its own MQTT session — so it
cannot cover non-gateway members of the private channel. Its
disclosure list is much longer than a position's
(`docs/firmware-config.md` §14), which is why it stays off by default.

### 10.2. `NODEINFO_APP` — implemented, but the material rarely arrives

A `NODEINFO_APP` rule is implemented and behaves like the position rule
minus the precision checks (there is no precision-like concept to
range-check). `origin_scope` is its only gate, and it is the one that
matters: relaying a *stranger's* NodeInfo would republish someone else's
name and hardware model to a public server.

The catch is structural, and was found only by trying it:

| NodeInfo variant | Channel it goes out on | Reaches `brokerd`? |
|---|---|---|
| the node's own periodic **broadcast** | the **primary** channel | **no** — the primary channel is deliberately never uplinked (`docs/firmware-config.md` §7) |
| a **reply** to an unknown node | whichever channel that node was heard on | only when a stranger appears on the private channel, and addressed to one node |

Every NodeInfo frame this deployment has ever stored was the second kind —
unicast, `to` a specific node, never `to` broadcast. So a NodeInfo rule
cannot be relied on to keep a node's name published; that is what
`MAP_REPORT_APP` is for (§10.1).

Relaying NodeInfo is still worth having enabled, for a reason unrelated to
maps: see §12 on ghost nodes.

### 10.3. `TELEMETRY_APP` (device metrics only) — free graphing on existing public front-ends

Also channel-based, same scope as §10.2. Public map front-ends
(`liamcottle`'s map, `map.mess.host`) already render per-node telemetry
graphs (battery, uptime, channel utilization) from this portnum — free
dashboarding without `brokerd` building its own charts. Scope: device
metrics only; environment telemetry doesn't apply (no sensors attached).
Lower priority than position/nodeinfo — a convenience, not tied to the
motivating use case.

### 10.4. `NEIGHBORINFO_APP` — reviewed, not worth adding

Channel-based like §10.2/§10.3, but low value here: drives the "lines
between nodes" map feature, and the office/home boards are isolated LoRa
nodes with no meaningful local neighbors to report. Revisit only if a
third, LoRa-linked node is ever added.

### 10.5. Explicitly excluded, permanently

`TEXT_MESSAGE_APP`, `ROUTING_APP`, `WAYPOINT_APP`, and any portnum that
can carry actual message content or precise internal topology are never
candidates for a rule, regardless of eligibility-predicate design — this
would defeat §1's whitelist model. Not a `Qn`; a permanent boundary.

## 11. First real publishes

Enabling a rule for real needed three attempts, each exposing a defect the
previous one hid: no log line for a publish, five `MeshPacket` fields missing
from the constructed packet, and a re-encoded payload that dropped the
position's timestamp. All three are fixed; the procedure that worked is §7's
(`dry_run` first, compare against a real capture, then flip).

## 12. Ghost nodes

Publishing a node that cannot listen makes other nodes try to reach it: each
sighting costs about two packets (a NodeInfo with `want_response`, and a
reply attempt). It can be reduced by publishing a name — a node with a
`LongName` is interrogated less — but not eliminated
(`meshtastic/firmware#5238`).

## 13. Deliberate limits, continued (see also §9)

- Whether to add a `MAP_REPORT_APP` rule as a complement for the gateway
  boards themselves (§10.1) is undecided. It cannot replace
  `coarse-position`.
