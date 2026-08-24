# Architecture Decision Records — Index

ADR-1 and ADR-2 are specific to the public-exposure decision and stay in
`docs/security.md` §1. This file indexes them and holds every
implementation-level ADR since — decisions that had to be settled to
implement `brokerd` but don't belong to any one document.

| ADR | Title | Recorded in |
|---|---|---|
| ADR-1 | Expose `brokerd` publicly | `docs/security.md` §1 |
| ADR-2 | Embed the MQTT broker via mochi-mqtt; decouple hosting from any one method | `docs/security.md` §1 |
| ADR-3 | Storage runs off the broker's relay path | this file |
| ADR-4 | Decrypt-failure handling | this file |
| ADR-5 | Auth-hook parameters | this file |
| ADR-6 | Channel-key reload is restart-only for v1 | this file |
| ADR-7 | Retention granularity and backup policy | this file |
| ADR-8 | TLS ownership: `go-acme/lego` (DNS-01) vs. external `certbot` | this file |
| ADR-9 | Decouple the architecture from specific board hardware | this file |
| ADR-10 | Serial↔MQTT proxy CLI relays `MqttClientProxyMessage`s, not a raw byte tunnel (amended) | this file |
| ADR-11 | Channel PSK encoding: base64, matching Meshtastic's own convention | this file |
| ADR-12 | Selective outbound relay to the official public MQTT server (position-first) | this file |
| ADR-13 | Never vendor/generate code from `meshtastic/protobufs`; implement the wire format independently | this file |
| ADR-14 | Duplicate delivery suppression keyed on `(gateway_id, packet_id)`, within a window or on byte identity | this file |

---

## ADR-3: Storage runs off the broker's relay path

- **Context**: `brokerd` embeds mochi-mqtt and the storage/decoding logic
  in one process (ADR-2). A bug in storage code must not be able to stall
  or crash the broker's own message relay — this is the accepted trade-off
  from ADR-2: storage/decoding logic must always
  absorb panics via `recover()`.
- **Decision**: the `OnPublish` hook does the minimum possible work
  synchronously — copy the raw payload (topic + bytes) into a bounded,
  buffered Go channel — and returns immediately. A separate worker
  goroutine reads from that channel and performs decode + SQLite writes.
  The worker wraps both its top-level loop and each individual message's
  processing in `recover()`, so one malformed message can log-and-continue
  instead of taking down the worker (let alone the broker).
  Queue-full policy: **drop and count**, never block the relay path
  waiting for room. The drop counter is exposed via
  `docs/monitoring-api.md`'s message stats endpoint.
- **Consequences**: under sustained overload, some messages are dropped
  from storage (never from relay — relay always succeeds or fails
  independently of storage). This is preferable to backpressure that could
  stall cross-site relay. The queue depth and drop counter must be watched
  in monitoring so silent data loss doesn't go unnoticed
  (`docs/runbook.md` §9).

## ADR-4: Decrypt-failure handling

- **Context**: an incorrect channel key, a channel not yet registered in
  `brokerd`'s config, or a genuinely corrupted frame can all cause
  decryption/decoding to fail. The raw-frame-first principle
  (`docs/architecture.md` §3) means failure must never prevent storage of
  the original bytes.
- **Decision**: on any decode failure, `brokerd`:
  1. Still inserts the `raw_frames` row (this happens unconditionally,
     before decode is attempted — see `docs/storage-schema.md`).
  2. Sets that row's `decode_status` to a failure reason
     (`unknown_channel` / `decrypt_failed` / `parse_failed`).
  3. Emits one structured log line with fields: topic, channel segment,
     packet id, gateway id, and the failure reason — **never** key
     material or decrypted/attempted-decrypted plaintext.
  4. Increments a decode-failure counter, broken down by reason, exposed
     via `docs/monitoring-api.md`'s `/api/v1/stats/messages` endpoint.
- **Consequences**: an operator can distinguish "channel key not yet
  configured" (expected, fixable by `firmware-config.md` §7's checklist)
  from "decrypt_failed on a known channel" (a real bug, e.g. a
  nonce-derivation mismatch) by watching the counters and log reasons,
  without needing to inspect raw bytes.

## ADR-5: Auth-hook parameters

- **Context**: mochi-mqtt's Ledger compares passwords in plaintext and has
  no built-in failure-based banning, so `brokerd` implements both as
  custom hooks (`docs/security.md` §3). Concrete parameters were left open
  until there was a deployment to size them against.
- **Decision**:
  - Password hashing: bcrypt, cost factor `12` (a common default balancing
    hash time against brute-force resistance for a low-QPS auth path).
  - Failure threshold: `5` failed attempts.
  - Ban duration: `30` minutes, sliding (a new failure while banned resets
    the window).
  - Failure counter storage: in-memory (a per-IP map with timestamps),
    **not persisted** — accepted loss on restart, since restarts are
    infrequent and a fresh window after a restart is an acceptable
    trade-off against the complexity of persisting it.
  - Manual unban: restart `brokerd`, or (once built) an admin CLI/endpoint
    reachable only over SSH — never on a public port (`docs/security.md`
    §4).
- **Consequences**: these are starting values, not permanent; if real
  scanning traffic shows the threshold/duration miscalibrated, tune them
  in `docs/brokerd-config.md`'s `auth.*` keys without needing a new ADR
  (the ADR fixes the mechanism and initial values, not that they're
  frozen).

## ADR-6: Channel-key reload is restart-only for v1

- **Context**: `docs/firmware-config.md` §7 step 3 left "whether hot-reload
  is supported" as "not yet made."
- **Decision**: for v1, adding or rotating a channel's PSK in `brokerd`'s
  config requires a restart. On `SIGTERM`, `brokerd` performs a graceful
  shutdown: stop accepting new broker connections, drain the storage
  queue (ADR-3) up to a bounded timeout, then exit. `systemd`
  (`Restart=always`) brings it back up with the new config.
- **Consequences**: adding a channel key causes a brief (target: under a
  few seconds) relay interruption. This is accepted for v1 given channel
  additions are expected to be rare (`docs/architecture.md` §10.1 — mostly
  driven by adding a new board, not routine operation). Hot-reload
  (e.g. `SIGHUP`-triggered config re-read) can be revisited later without
  changing the storage/relay architecture.

## ADR-7: Retention granularity and backup policy

- **Context**: `docs/architecture.md` §9 needed a concrete config shape
  instead of a single vague `retention_days`; `docs/security.md`/
  `docs/architecture.md` left backup-before-delete as undecided.
- **Decision**: two independent settings,
  `retention.raw_frames_days` and `retention.decoded_days`, both defaulting
  to **30 days** when the key is absent (`0` written explicitly still means
  unlimited; negative values are rejected at load — full reference in
  `docs/storage-schema.md` and `docs/brokerd-config.md`). The default is
  bounded deliberately: an operator who never configured retention should
  not silently accumulate message content and metadata forever, which is
  both a privacy exposure (`docs/security.md`) and unbounded disk growth. Deletion is a hard `DELETE` (no soft-delete
  flag), run on a periodic schedule (e.g. daily, via an internal ticker —
  no external cron dependency). **No automatic backup before deletion in
  v1** — retention deletion is destructive by design, matching "storage
  management," not "archival." Anyone wanting an archive should back up
  the whole SQLite file on their own schedule (`docs/runbook.md` §9),
  independent of the retention deletion job.
- **Consequences**: operators who want history beyond the configured
  retention window must set `retention.*_days = 0` (unlimited) and manage
  disk growth manually, or maintain their own periodic file-level backups.
  This keeps the deletion job simple and avoids `brokerd` growing archival
  responsibilities it doesn't need yet.

## ADR-8: TLS ownership — `go-acme/lego` (DNS-01) vs. external `certbot`

- **Context**: `docs/deployment.md` and `docs/security.md` left this as
  "to be decided during implementation". The original decision
  specified `golang.org/x/crypto/acme/autocert` for this, but `autocert`
  turned out to only implement the "http-01" and "tls-alpn-01" challenge
  types — it has no DNS-01 support at all (discovered during
  implementation, not knowable from the package name alone). This
  amends that choice; the underlying goals (no port 80, in-process
  automatic issuance/renewal, no external cron) are unchanged.
- **Decision**: `brokerd` manages its own certificates via
  `github.com/go-acme/lego/v4` used as a library (`internal/tlscert`),
  performing the **DNS-01** challenge so port `80` never needs to be
  opened. The DNS provider is selected by name
  (`listener.tls_dns_provider`, e.g. `"cloudflare"`) against a small,
  explicit registry (`internal/tlscert/providers.go`) — deliberately
  **not** lego's own `providers/dns.NewDNSChallengeProviderByName`,
  which imports all ~200 of lego's provider packages (and their SDKs:
  AWS, Azure, GCP, Alibaba, Tencent, etc.) unconditionally, ballooning
  the dependency graph by hundreds of indirect modules just to support
  one provider (also discovered during implementation). Adding a new
  provider means importing its lego package and adding one line to the
  registry — a small, explicit cost traded for not vendoring 200 cloud
  SDKs. The obtained certificate is served via a `*tls.Config` reused
  for the `8883` MQTT listener. (Originally it also served the `443`
  monitoring listener; that surface now binds loopback and is published by
  a reverse proxy which terminates TLS itself, so brokerd's certificate is
  used only by MQTT — see `docs/monitoring-api.md` §0.)
- **Consequences**: removes the external `certbot` + renewal-cron
  dependency and the operational split between two independent TLS
  lifecycles — `internal/tlscert.Manager.RunRenewalLoop` renews
  in-process on a fixed schedule, checking each certificate's expiry
  against a 30-day-before-expiry threshold. Requires the DNS provider's
  credentials to be available to `brokerd` via that provider's own
  conventionally-named environment variable (e.g. Cloudflare's
  `CLOUDFLARE_DNS_API_TOKEN`) — never referenced indirectly via a
  config.json `*_env` key, since lego providers each expect a fixed env
  var name they choose, not an operator-configurable one; this is a
  deliberate, documented exception to `docs/security.md` §7's usual
  `*_env` indirection pattern. A `listener.tls_use_staging_ca` flag
  switches to Let's Encrypt's staging directory (looser rate limits,
  untrusted certs) for verifying the DNS-01 flow before pointing at
  production — verified end-to-end against the real domain and the real
  Cloudflare zone during implementation. If DNS-01 automation for a
  given provider proves impractical, falling back to external `certbot`
  + HTTP-01 remains possible without changing anything else in the
  architecture.

## ADR-9: Decouple the architecture from specific board hardware

- **Context**: every document originally described the two boards as
  specifically "Heltec V4," and several architectural statements (§1's
  goal, the connectivity-model diagram, BLE-behavior notes) were phrased
  as if that model were an architectural requirement rather than an
  incidental choice. In practice, nothing `brokerd`, the protocol layer
  (`docs/protocol-spec.md`), or the storage schema
  (`docs/storage-schema.md`) does depends on the board's chipset, radio,
  or BLE behavior — only on "runs Meshtastic firmware with WiFi + MQTT
  module support" (`docs/hardware.md` §1).
- **Decision**: separate "architectural board requirements"
  (`docs/hardware.md` §1, referenced from `docs/architecture.md` §10.4)
  from "the current hardware instance's specifics" (`docs/hardware.md`
  §2, Heltec V4/ESP32-specific facts like BLE/WiFi exclusivity and the
  CP210x/CH9102 driver). Every document that stated an ESP32-specific fact
  as if it were project-wide now says so explicitly and points back to
  `docs/hardware.md` §1's caveats.
- **Consequences**: adding a third site, or replacing either board with a
  different model, requires re-verifying only the specific facts in
  `docs/hardware.md` §2 for the new board — not touching `brokerd`'s design, the
  protocol spec, or the storage schema. This mirrors the reasoning already
  applied to board *count* in `docs/architecture.md` §10.1; this ADR
  applies the same reasoning to board *model*. No implementation exists
  yet, so this ADR only affects documentation wording, not code.

## ADR-10: The serial↔MQTT proxy relays `MqttClientProxyMessage`s, not a byte tunnel

- **Context**: a board with no WiFi can only reach `brokerd` through
  `mqtt.proxy_to_client_enabled`. In that mode the board opens **no** TCP/TLS
  socket. Per `mesh.proto` (read, never vendored — ADR-13) it sends a
  `MqttClientProxyMessage` (`topic`, opaque `data`, `retained`) inside
  `FromRadio` over the Phone API framing it already uses for serial, BLE and
  TCP:4403. The peer is expected to be a real MQTT client that publishes and
  subscribes on the board's behalf, as the `LN4CY/mqtt-proxy` reference
  implementation does — reading the board's own `mqtt.*` module config so
  nothing is configured twice.
- **Decision**: `cmd/mshserial-mqtt-proxy` speaks the Phone API framing over
  serial and is itself a real MQTT client to `brokerd`, authenticating with
  credentials read from the board. The channel-level payload (already
  PSK-encrypted `ServiceEnvelope` bytes) stays opaque to it: the CLI never
  parses an envelope or touches a channel PSK.
- **Consequences**: the proxy machine **is** a trusted party for transport —
  it holds that board's MQTT password and terminates TLS itself, so a
  compromise there lets an attacker authenticate as that board (but not read
  channel-encrypted content). This supersedes an earlier, weaker claim in
  `docs/security.md` §4. Implementation needs the Phone API serial framing, a
  small `ToRadio`/`FromRadio`/`AdminMessage` subset, and an MQTT client
  library already in the dependency set. It stays a separate binary from
  `brokerd` with no shared `internal/*` package. Deferred until a WiFi-less
  board is actually adopted.

## ADR-11: Channel PSK encoding — base64, matching Meshtastic's own convention

- **Context**: `docs/brokerd-config.md`'s `channels[].psk_env` left the
  PSK's text encoding as "base64 or hex, TBD at implementation time."
  Meshtastic's own tooling — the app UI's channel key display, the CLI
  (`--ch-set psk base64:{key}`), and channel share URLs/QR codes —
  uniformly represents the PSK as **base64** (e.g. the default channel's
  well-known PSK is displayed as `AQ==`).
- **Decision**: `brokerd` reads each channel's PSK from its named env var
  (`docs/security.md` §7) as **standard base64, with padding**. No hex
  option is supported.
- **Why**: an operator copying the PSK out of the Meshtastic app or CLI
  can paste it into the `.env` file unchanged — no manual re-encoding
  step, which is exactly the kind of manual conversion that turns a
  32-byte secret transcription into an error-prone task. Supporting both
  encodings would only add an ambiguous format-sniffing step for no
  benefit, since every source of a real PSK value already produces
  base64.
- **Consequences**: `internal/config`'s loader must base64-decode
  `psk_env` values and treat a decode error or a decoded length other
  than 32 bytes as a startup error (fail fast, not a warning) — folded
  into `docs/brokerd-config.md`'s validation rules alongside the existing
  "required env var unset/empty" check.

## ADR-12: Selective outbound relay to the official public MQTT server (position-first)

- **Context**: `docs/architecture.md` §10.2 originally deferred *all*
  bridging to external brokers (full federation) as out of scope,
  citing privacy risk and `MeshMonitor` already covering the generic
  case. A much narrower need surfaced: letting an operator optionally
  make a board's presence visible on public Meshtastic maps (meshmap.net
  and equivalents, which all read the same official public MQTT server)
  by relaying only already-coarse position data — without exposing the
  private `pvt` channel's actual messages, and without reopening full
  bidirectional federation.
- **Decision**: add a **selective outbound relay** feature to `brokerd`
  — publish-only, rule-based, opt-in per board and per rule, with
  exactly one built-in target (the official public server) in v1. Full
  design: `docs/outbound-relay.md`. This is adopted as §10.2.2, a
  distinct decision from §10.2.1 (full federation), which **remains
  deferred**. Eligibility for a rule is controlled by `origin_scope`
  (`docs/outbound-relay.md` §3): the default, `"channel_members"`,
  covers any member of the relaying channel (not just `brokerd`'s own
  gateway boards) — because the real consent signal is a member's own
  deliberate `position_precision` setting, not which account gatewayed
  the packet. `"own_boards_only"` (matched against `raw_frames.from_node`
  and each board's configured `node_id`) is available as a stricter
  opt-in. Eligibility also requires `latitude_i`/`longitude_i` to both be
  present, checked before the precision-range check — boards broadcast
  position on a fixed timer regardless of GPS fix, so an empty/no-fix
  broadcast must be rejected explicitly rather than assumed excluded by
  the precision check alone.
- **Why this doesn't reopen the federation deferral**: the three risks
  that motivated deferring §10.2.1 (loop suppression, blind mirroring,
  metadata leakage from the private channel) are each addressed
  structurally rather than by configuration discipline: publish-only
  (no loop-suppression problem, because nothing flows back in),
  whitelist-based rules (nothing is mirrored unless a rule explicitly
  matches its portnum), and eligibility gated on data the *board* already
  chose to make coarse (the private channel's content is never eligible
  for any rule, by construction — there is no rule type for arbitrary
  message content).
- **Consequences**: `internal/decode` needs its `POSITION_APP` decoder
  built sooner than `docs/protocol-spec.md` §4's original "later"
  priority implied, if this feature ships before telemetry/nodeinfo
  decoding. The AES-256-CTR engine built for decrypting the boards' own
  channel must be written symmetrically (encrypt and decrypt) so this
  feature's default-PSK encryption reuses it rather than adding a second
  crypto implementation. A `dry_run` mode (`docs/outbound-relay.md` §7)
  ships as the default so the feature can be fully exercised without
  ever publishing to the real, shared, external server — flipping it off
  is a deliberate, separate step for whoever operates `brokerd`.

## ADR-13: Never vendor/generate code from `meshtastic/protobufs`; implement the wire format independently

- **Context**: `meshtastic/protobufs` (the `.proto` schema definitions for
  `ServiceEnvelope`/`MeshPacket`/`Data`/`Position`/etc., which
  `docs/protocol-spec.md` is written against) is licensed under plain
  **GPL-3.0**, with no linking exception — confirmed directly from the
  repository's `LICENSE` file. A community proposal to relicense it (or
  add a linking exception) for exactly this kind of downstream-client
  use case was raised and explicitly rejected by the maintainers
  (`meshtastic/protobufs#695`). Running `protoc` against their `.proto`
  files and linking the generated Go code into `brokerd` would very
  plausibly make `brokerd` a work "based on" GPL-licensed code, which
  would require the whole binary to be distributed under GPL-3.0 —
  directly conflicting with this project's stated MIT license
  (`README.md`).
- **Decision**: `brokerd` (and any other binary in this repository)
  **never vendors or code-generates from `meshtastic/protobufs`'s
  `.proto` files.** All wire-format handling for Meshtastic messages
  (`ServiceEnvelope`, `MeshPacket`, `Data`, `Position`, and any future
  portnum payload) is implemented independently in Go, based on the
  publicly documented wire format (field numbers/wire types) — the same
  approach `docs/protocol-spec.md` already takes by describing the
  format in prose rather than importing their schema file directly. The
  project's license stays **MIT**.
- **Why this doesn't create an ongoing maintenance burden**: protobuf's
  wire format is additive-by-design — a decoder that reads known field
  numbers and skips unrecognized ones tolerates upstream schema growth
  without any changes, and reusing/renumbering an existing field number
  would break every real Meshtastic firmware/client in the field, not
  just this project, so the ecosystem has a strong incentive never to do
  it. Maintenance work is only needed when *this* project chooses to
  start supporting a new field/portnum (e.g. adding `TELEMETRY_APP`
  later, `docs/outbound-relay.md` §10.3) — opt-in work either way,
  independent of which implementation approach was chosen.
- **This applies to the documentation too**: upstream behaviour is
  *described*, never quoted as source. `docs/` carries no verbatim code from
  `meshtastic/firmware` (GPL-3.0) or from other projects under copyleft terms
  (`meshmap.net` is AGPL-3.0) — the condition or the value is stated in prose
  or a table, with the file named so a reader can check it at the tag.
- **Consequences**: `internal/decode`'s Go structs and parsing logic are
  hand-written and tested against real captured bytes (`testdata/`,
  `docs/protocol-spec.md` §5), not generated. This is consistent with
  the standing requirement to verify wire behavior against
  real hardware regardless of implementation approach — schema-derived
  code would still need the same empirical verification, since firmware
  *behavior* (e.g. nonce derivation) isn't fully captured by the schema
  alone. No source files from `meshtastic/protobufs` (or any other
  GPL-licensed Meshtastic repository) are ever copied into this
  repository.

## ADR-14: Duplicate delivery suppression keyed on `(gateway_id, packet_id)`

- **Context**: firmware re-delivers the same packet — one board was observed
  sending an identical `packet_id` three times at ~7–8 second intervals,
  producing three `text_messages` rows for one sent message. The docs
  described suppression that no code implemented.
- **Decision**: suppress in the storage worker on `(gateway_id, packet_id)`
  within a bounded window (`internal/storage.DedupWindow`, 5 minutes):
  - the `raw_frames` row is **always** written (ADR-3/ADR-4's
    raw-frame-first principle), recorded as `decode_status = duplicate`;
  - no decoded row is written, and **no outbound relay** is attempted —
    republishing the same position on every firmware retry is exactly the
    inconsiderate use `docs/outbound-relay.md` §7 warns about;
  - a duplicate of a *failed* frame keeps its failure reason, which is worth
    more as a diagnostic;
  - the lookup **fails open**: losing a real message is worse than storing a
    duplicate.
- **A byte-identical payload is a duplicate at any age.**
  A window is the right tool for a firmware retry, whose bytes differ from the
  original in `hop_limit` and the reception fields. It cannot bound a
  *re-publish*: a gateway sends the packet still in its queue when it
  reconnects, and a brokerd restart is what makes it reconnect -- so the gap
  is whatever the operator waited, unbounded by any window. Observed at
  5m48s, which stored one text message twice, showed it twice on the
  monitoring page and notified twice.
  Widening the window only narrows that hole, since the delay is however long an
  operator waits between restarts. So the second rule has no time bound: the
  same `(gateway_id, packet_id)` with a payload identical to the byte, ciphertext
  and nonce included. Packet ids are random 32-bit values, so two distinct
  packets sharing an id *and* their ciphertext is not a case that occurs, and
  both rules use the existing `(gateway_id, packet_id)` index, so neither costs a
  scan. A re-delivery carrying *different* bytes is still kept, which is what the
  non-UNIQUE index was for.

- **A packet id of 0 means the packet did not state one, and never
  deduplicates.** `MAP_REPORT_APP` carries no packet id at all
  (`docs/firmware-config.md` §14), so keying on 0 made every id-less frame from
  one gateway a duplicate of the previous one. Four real map reports were
  suppressed that way in this deployment, and because the worker skips the
  outbound relay for a duplicate, they were never relayed either. The rule is
  ADR-15's, applied here: absent is not zero. The guard lives inside
  `IsDuplicate` so no caller can forget it
  (`TestIsDuplicate_PacketIDZeroNeverDeduplicates`).
- **Why bounded, and why include `gateway_id`**: packet IDs are random
  32-bit, so a collision inside five minutes is not a practical concern,
  while an unbounded window would suppress a legitimate later re-delivery —
  which is why `docs/storage-schema.md`'s index is deliberately non-UNIQUE.
  Two boards gatewaying the same mesh packet stay distinct deliveries, since
  each board's view is independently useful. The window is a constant, not a
  config key: it tracks firmware retry behaviour, not deployment volume.
- **Consequences**: `raw_frames` counts exceed decoded counts by the retry
  rate — expected, and a useful health signal (the `duplicate` bucket in
  `docs/monitoring-api.md`). `internal/storage/dedup_test.go` asserts on
  `EXPLAIN QUERY PLAN` so the lookup cannot regress into a table scan.
- **Scope**: this suppresses transport-level re-delivery, not identical text
  arriving under a *different* `packet_id`. Two identical messages sent
  deliberately are two messages, and no broker can distinguish them from a
  retransmission assigned a fresh ID; collapsing them is a presentation
  concern.

## ADR-15: Store every field the MQTT traffic carries, and record "not stated" as NULL

- **Context**: the decoder parsed only what the outbound relay needed, so
  `rx_snr`, `rx_rssi`, `want_ack`, `via_mqtt` and every `Data` field beyond
  portnum and payload were parsed and thrown away — reception quality that no
  other layer carries and that cannot be reconstructed afterwards. A decoded
  payload was stored only for `TEXT_MESSAGE_APP`, so 189 rows of
  `decode_status = 'decoded'` could not be told apart: a position, a nodeinfo
  and a telemetry frame all looked identical. A monitoring view of "what kind
  of traffic, how well received" had nothing to read.
- **Decision**: record everything the frame states. The MeshPacket and Data
  fields are stored on `raw_frames`, and `decoded_payloads` holds one
  JSON row per interpreted payload (`docs/storage-schema.md` §2.1). Decoders
  for `NODEINFO_APP`, `TELEMETRY_APP` and `ROUTING_APP` were added; a portnum
  with no decoder still writes no decoded row.
- **NULL means "the frame did not state this"**, and is never collapsed with
  0. `rx_snr = 0.0` is a measurement of 0 dB; `rx_snr IS NULL` means the
  gateway generated the packet itself and never heard it over RF. Protobuf
  does not transmit a zero-valued scalar, so a parsed 0 and an absent field
  are indistinguishable at the wire level — the `Has*` flags on the decoder's
  structs are what keep them apart, and the same rule governs absent JSON keys
  in `decoded_payloads.fields`.
- **Why JSON instead of a table per portnum**: a new portnum then costs a
  decoder and nothing else. The trade-off accepted is that a typed column is
  faster and self-documenting; at this volume (~4 frames/hour)
  `json_extract` is not a constraint, and the schema stops changing every time
  a new payload becomes interesting.
- **Consequences**: `decode_status = 'unhandled_portnum'` becomes rarer —
  `NODEINFO_APP` and `ROUTING_APP` frames that previously landed in that
  bucket are now `decoded`, so the historical counter is not comparable across
  this change. Retention gained a sweep for `decoded_payloads` rows whose raw
  frame is already gone, since a shorter `raw_frames` retention would
  otherwise leave them dangling. Ground truth for the float decode is a real
  capture whose gateway independently logged "SNR 6 dB" on its own console
  (`testdata/rf_received_1.*`), not this project's encoder.

## ADR-16: No migration runner — one schema file, applied with IF NOT EXISTS

- **Context**: storage carried an embedded migration runner (ordered `.sql`
  files, a `schema_version` table, one transaction per file). It was used
  exactly twice: once to create the schema, once to add ADR-15's columns.
- **Decision**: keep the whole schema in one embedded `schema.sql`, applied
  with `CREATE TABLE / CREATE INDEX IF NOT EXISTS` on every `Open`. Drop the
  runner, the version comparison and the `schema_version` table.
- **Why**: a migration framework exists to bring *other people's* databases
  forward. This project has one deployment and has never been distributed, so
  the runner's entire value was doing by hand, once, what can be done by hand,
  once. `IF NOT EXISTS` still makes a fresh database and the existing one
  converge, and re-opening stays a no-op.
- **Consequences**: a future schema change means editing `schema.sql` **and**
  running the same `ALTER` against the live database manually
  (`docs/storage-schema.md` §5) — the runner would have done that step. If this
  is ever deployed anywhere else, the runner has to come back before the second
  deployment, not after. `decode_version` survives the removal as
  `storage.DecodeVersion`: it stamps rows with the decoder generation that
  wrote them, which the reprocessing path needs and which was never a schema
  concern.

## ADR-17: Event hooks are notifications, with two sinks and no delivery guarantee

- **Context**: everything `brokerd` learns stayed inside it. Reading a message
  meant querying SQLite, and knowing a board had dropped meant reading a
  counter. The alternative considered first was an external poller against the
  monitoring API, which would have needed a new inbound path into a service
  that deliberately binds loopback.
- **Decision**: `brokerd` pushes. One event model (`frame`,
  `board_connected`, `board_disconnected`), one payload shape, and two sinks:
  an HTTPS POST or a local program (`docs/event-hooks.md`). Rules are
  whitelist-only, `dry_run` defaults to on when absent, and hooks fire after
  the durable write, never before.
- **Not a delivery guarantee**: the queue is bounded and drops its oldest
  entry, a failed delivery is counted and abandoned, and a target that fails
  repeatedly is disabled until restart. Anything that needs completeness reads
  the database, which is why no durable spool was added.
- **Retries only for webhooks.** Re-POSTing is what an HTTP receiver expects;
  re-running a program that may already have had an effect is worse than
  reporting the failure, so a command target is attempted exactly once and the
  config rejects a non-zero `retries` on it.
- **`kind: command` is where this project stops being report-only.** A hook
  command must be an absolute path, a regular file, executable and not
  writable by group or other, or the config fails to load — because whoever
  can write that file decides what `brokerd` executes. Three further
  properties are structural: no shell, the payload on stdin rather than in an
  argument, and a minimal environment instead of `brokerd`'s own, which holds
  channel PSKs and API tokens.
- **The message body is opt-in per target** (`match.include_text`), and a
  template cannot reach around it: exposure of plaintext to a third party is
  the one consequence that cannot be undone afterwards.
- **Consequences**: config gained an `event_hooks` block with a validation
  surface larger than any other (kind/URL scheme/secret presence/command
  permissions/quiet-hours syntax/template syntax), all of it checked at load
  so a typo fails at startup. Seven counters per target are exposed over the
  monitoring API, including `disabled_targets` — the only place `brokerd`
  reports an action it took on its own. `-test-hooks` delivers one synthetic
  event per kind so a new target can be checked at a chosen moment instead of
  by waiting for the mesh.

