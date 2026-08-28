# Firmware Configuration

This document is the single source of truth for the Meshtastic settings to
apply to the office/home boards (currently two Heltec V4 units —
`docs/hardware.md` §2; the settings below apply to any board satisfying
`docs/hardware.md` §1's general requirements, with board-specific values
called out where they differ). Real values (WiFi passwords,
PSKs, etc.) are never written here — only `<PLACEHOLDER>` forms. Secrets
handling follows `docs/security.md`.

> **Unverified**: the values below represent design intent and have not yet
> been verified on real boards/firmware versions.

## 1. Common assumptions

- Firmware: the latest official Meshtastic stable release. The web flasher
  confirmed a supported firmware image exists for the Heltec V4
  (`docs/environment.md`, `docs/hardware.md` §2). **Confirmed on the
  first test board**: `firmwareVersion: 2.7.26.54e0d8d`, `hwModel:
  HELTEC_V4`, `hasPKC: true` (via `meshtastic --info`). Exact board
  revision (V4.2.0/V4.3.1/etc.) still needs a physical
  silkscreen/label check. If a different board model is
  ever substituted, re-confirm firmware support for that model first
  (`docs/hardware.md` §1).
- No GPS module installed on either of the two currently deployed boards
  → all position-related settings assume "not present." This is a
  per-board fact (`docs/hardware.md` §1), not a project-wide rule — a
  board with GPS attached would set `position.gps_mode` differently.
- Both boards run on constant power without a battery.
- There is a single broker, `brokerd`, deployed on a public Linux server
  (`docs/architecture.md` §3–4, `docs/deployment.md`). **By default the two
  boards use symmetric settings** — only the connection address
  (domain/port) is shared, and everything else is identical. The only
  exception is if `brokerd` is run from a home lab and that site's board is
  connected directly over the local LAN (`docs/deployment.md`'s "special-
  casing the home board").
- **Firmware constraint**: `mqtt.address` is a single string and does not
  support primary/secondary redundancy (confirmed against the protobuf,
  `docs/architecture.md` §2).

## 2. Bluetooth

> Official documentation quote: "ESP32 Devices: Bluetooth will be disabled
> if WiFi is enabled. The WiFi setting takes precedence."
> (meshtastic.org/docs/configuration/radio/bluetooth)
>
> **This is an ESP32-specific fact**, true for the currently deployed
> Heltec V4 boards, not a Meshtastic-wide guarantee — see
> `docs/hardware.md` §1's caveats before assuming it holds for a
> different board model.

- Regardless of the `bluetooth.enabled` value, **BLE pairing/connections
  won't work while WiFi is active** on the currently deployed boards.
  This is common ESP32 behavior and cannot be configured around; it would
  need re-verifying for a non-ESP32 board (`docs/hardware.md` §1).
- Conclusion: since both boards keep WiFi on at all times in this project,
  the companion app connects over **WiFi/TCP (4403)**, not BLE.

## 3. Network (WiFi)

| Key | Value | Notes |
|---|---|---|
| `network.wifi_enabled` | `true` | |
| `network.wifi_ssid` | `<PLACEHOLDER>` (per site) | Must be a 2.4GHz-capable SSID |
| `network.wifi_psk` | `<PLACEHOLDER>` (per site) | Secret — never write the real value here |
| `network.address_mode` | `DHCP` (default) | |
| `network.ntp_server` | keep default | |

- Companion app target: the board's IP, or (if there's only one board on
  the same segment) `meshtastic.local`, on the firmware's default **TCP
  4403**. This path is identical on both boards and independent of the MQTT
  configuration.
- **If `network.wifi_psk` needs to change (e.g. the office WiFi's
  quarterly password rotation)**: BLE stays disabled while
  `wifi_enabled = true` even if the WiFi connection itself has failed, so
  the companion app has no path in over BLE or WiFi at that point. Update
  the PSK over **USB serial** instead — see `docs/runbook.md` §7 for the
  exact procedure.

## 4. LoRa / Region

| Key | Value | Notes |
|---|---|---|
| `lora.region` | `KR` | For domestic use, identical on both boards |
| `lora.modem_preset` | `LONG_FAST` (proposed, must match on both boards) | The channel hash depends on the preset |
| `lora.hop_limit` | `3` (default) | Not very meaningful with only one node per site today; kept for future expansion |
| `lora.tx_enabled` | `true` | Keep even with no RF neighbors yet (future local expansion) |
| `lora.ignore_mqtt` | `false` | So MQTT-relayed packets aren't ignored. **Set explicitly, never assumed** — one of the two deployed boards shipped with this `true` (§13) |

## 5. Position (no GPS module on either of the current two boards)

| Key | Value |
|---|---|
| `position.gps_mode` | `NOT_PRESENT` | **Verified consequence of getting this wrong**: left at `ENABLED` on a board with no GPS, the firmware broadcasts `POSITION_APP` packets with latitude/longitude of **zero**, interleaved with any real fixed position. They decode cleanly, so nothing flags them (§15).
| `position.fixed_position` | `false` |
| `position.position_broadcast_smart_enabled` | `false` |

> **If the optional selective outbound relay feature is ever enabled**:
> these settings are exactly why that feature has nothing to relay today.
> Full prerequisites and the required/recommended breakdown are in
> §11.C and `docs/outbound-relay.md` §2 — not required for the core
> private bridge (`brokerd`) to work.

## 6. Power

| Key | Value | Notes |
|---|---|---|
| `power.is_power_saving` | `false` | Constant power, no need to save; also required to keep WiFi up |
| `device.role` | `CLIENT` (default) | Based on the current single-node-per-site stage |

## 7. MQTT module (default: symmetric on both boards)

| Key | Value | Notes |
|---|---|---|
| `mqtt.enabled` | `true` | |
| `mqtt.address` | `<brokerd public domain>:8883` | Same on both boards (symmetric default). The firmware accepts an explicit `host:port` (confirmed in `src/mqtt/MQTT.cpp`'s `parseHostAndPort`) and otherwise falls back to `1883` (plaintext) or `8883` (TLS) by default. `8883` is the standard MQTT-over-TLS port and is used explicitly here for clarity. Can be a local IP (no port needed, defaults to `1883`) for the home board only, if deployed from a home lab |
| `mqtt.tls_enabled` | `true` | Same on both boards (symmetric default). Can be `false` for the home board if it connects over the local LAN directly |
| `mqtt.root` | `msh/pvt` | A dedicated namespace instead of the default `msh`, to avoid mixing with public conventions |
| `mqtt.encryption_enabled` | `true` | Keeps channel-PSK encryption on the MQTT hop. **Stock is `false`, which publishes decrypted packets whatever the channel key** — see §11 A |
| `mqtt.json_enabled` | `false` | Prevents plaintext JSON leakage |
| `mqtt.map_reporting_enabled` | `true` in this deployment | Deliberately on, and **only** because the outbound relay is meant to publish map reports to the public server (§11 C, §14, `docs/outbound-relay.md`). Enabling it does **not** by itself put a board on a public map — the report goes to the *configured* broker, which here is `brokerd`. Off is the right value for any deployment not using that feature, and it needs a second opt-in (`should_report_location`) to emit anything at all |
| `mqtt.proxy_to_client_enabled` | `false` | Not needed by default (assumes the board can reach the internet over its own WiFi). See the fallback in §8 |
| `mqtt.username` / `mqtt.password` | `<PLACEHOLDER>` (per account) | See `docs/security.md` §3. Passwords are stored as bcrypt hashes in `brokerd`. ⚠️ **`mqtt.password` holds at most 31 characters** and there is no warning if you exceed it — see §12 |

- Office board: `mqtt.username = alpha`
- Home board: `mqtt.username = bravo`
- These two are the concrete instance of the general per-board account
  pattern described in `docs/architecture.md` §10.1 — adding a third board
  later just means adding one more account/ACL entry, not redesigning
  anything.

### Primary channel (`LongFast` or whatever it's named) — deliberately not relayed

- `uplink_enabled = false` and `downlink_enabled = false` on the primary
  channel, **set explicitly rather than left at whatever the default
  happens to be.** Confirmed against `meshtastic/protobufs`'
  `channel.proto`: both are proto3 `bool` fields, which default to
  `false` unless a channel is deliberately configured otherwise — but we
  pin this explicitly so the intent is auditable in config, not implied.
- This means the primary channel's traffic (and any similarly-unconfigured
  channel) **structurally cannot reach `brokerd`**, regardless of ACL —
  the board itself never uplinks/downlinks it. See
  `docs/architecture.md` §2 for the RF-layer vs. MQTT-layer distinction
  (the board may still locally hear/relay this channel's LoRa traffic from
  any real nearby Meshtastic nodes; that has nothing to do with `brokerd`).
- Also worth knowing: a freshly created channel's default PSK (the
  "shorthand 1" special value in `ChannelSettings.psk`) is a fixed,
  publicly known byte sequence baked into the firmware source — so an
  unconfigured primary channel is not just unrelayed, its content isn't
  meaningfully private in the first place.
- Not to be confused with `lora.config_ok_to_mqtt` ("OK to MQTT"), which is
  about whether *other* nodes' gateways may uplink **this node's** packets,
  not about whether this channel is relayed. It is a separate, per-sender
  setting and applies whatever the channel's key — §16.

### Dedicated channels (the ones actually relayed through `brokerd`)

- Create a dedicated channel (this document calls it `pvt`; real names are
  never written here) and give it to every participant.
- Set `uplink_enabled = true` and `downlink_enabled = true` on the gateway
  boards.
- Every participant must use the **same 32-byte PSK**; the actual value lives
  only in `.env`/a secrets manager, never in this document.
- **More than one such channel is normal.** `brokerd`'s `channels[]` is a list
  and the topic grammar keys on the channel name (`docs/protocol-spec.md` §1),
  so nothing here is single-channel; `pvt` is one example, not a limit. Each
  additional channel repeats the checklist below in full — including the
  `brokerd`-side key registration, without which its traffic is stored as
  opaque `raw_frames`.
- A channel does **not** have to exist on every board. One carried by a single
  gateway simply has a single uplink path: no second board will pick its
  traffic up if that one is offline, and it has no cross-site downlink. That is
  a consequence to know, not a fault — record which boards carry which channels
  in `docs/environment.md`.

### Mobile / battery-powered nodes (non-gateway)

> Both of this project's own gateway boards are constant-power (§1); the
> non-gateway nodes described here are additional participants. A third and a
> fourth such node are under test, and the uplink path is **confirmed**: with
> `lora.config_ok_to_mqtt` set on the node, its private-channel traffic
> reaches `brokerd` through a gateway (§16, procedure in `docs/runbook.md`
> §5.6). One of them is a `SEEED_WIO_TRACKER_L1` (nRF52840-based, no WiFi per
> `docs/hardware.md` §1's market note). Node IDs and names are left out here
> deliberately, as everywhere else in `docs/`.

**`uplink_enabled`/`downlink_enabled` only do something on a node that also
has `mqtt.enabled = true` (i.e. currently: the office/home gateway boards).**
The flag controls whether *that node itself* wraps LoRa-received packets
into MQTT publishes (uplink) or subscribes/rebroadcasts MQTT-received
packets onto LoRa (downlink) — see `docs/architecture.md` §2. A node
without an MQTT connection has nothing to wrap-and-publish or
subscribe-and-rebroadcast, so setting these flags on it has no effect.

Consequences for a battery-powered node joining a relayed channel:

- **Required**: the same channel name + the same 32-byte PSK as the
  gateway boards (this is what lets it talk to them over LoRa at all).
- **Not required, and pointless to set**: `mqtt.enabled`, `uplink_enabled`,
  `downlink_enabled`, `mqtt.encryption_enabled`. The last one is worth naming
  explicitly because §11 A calls it the second most consequential setting in
  this document: it governs whether *the publishing node* encrypts on the MQTT
  hop, and a non-gateway node never publishes to MQTT — the gateway that
  uplinks its packets decides. Leave WiFi off entirely — the node connects to
  the companion app over BLE instead (BLE and WiFi are mutually exclusive on
  ESP32, §2), which keeps deep-sleep power saving available.
- **Required on the node itself**: `lora.config_ok_to_mqtt = true` — the one
  MQTT-related setting that is not pointless on a non-gateway node, and one
  nothing else can grant on its behalf. It also has consequences outside this
  deployment: §16 before enabling it.
- With the shared channel key and that flag both in place, the gateway boards
  (whose channel copy already has `uplink_enabled = true`) pick up the node's
  LoRa traffic on that channel and relay it to `brokerd`; no other setting on
  the node is involved. boards (whose channel copy already
  has `uplink_enabled = true`) pick up the mobile node's LoRa traffic on
  that channel and relay it to `brokerd` — no other mobile-node
  configuration is involved.

**Power consequence: none, either way.** Whether `uplink_enabled`/
`downlink_enabled` are set has no bearing on a battery node's power draw,
because that node never performs the MQTT-side work the flags gate — it
just keeps transmitting/receiving LoRa exactly as it would on any other
channel. The only setting that meaningfully affects battery life is
whether **WiFi** is enabled at all (`network.wifi_enabled`): enabling it
adds a continuous ~100–150 mA draw and prevents the deep-sleep modes
`power.is_power_saving` otherwise allows. A battery node has no reason to
enable WiFi unless it is itself meant to become a gateway.

#### Checklist: adding a new channel intended to flow through `brokerd`

Three separate prerequisites have to all be satisfied — two on the board
side, one on `brokerd`'s side:

1. **Board side (required for relay to happen at all)**: create the
   channel with the same name + PSK on every board/node that should
   participate (gateway boards **and** any mobile/battery nodes sharing
   the channel). Enable `uplink_enabled`/`downlink_enabled` on the
   gateway boards only — the ones that also have `mqtt.enabled = true`;
   setting these flags on a node without an MQTT connection has no effect
   (see "Mobile / battery-powered nodes" above). Without a matching
   channel key, a board/node never even attempts to publish/subscribe on
   that channel — `brokerd`'s own configuration is irrelevant.
2. **Sending-node side (required for any *non-gateway* participant)**: set
   `lora.config_ok_to_mqtt = true` on each such node, or the gateway hears
   its packets over LoRa and declines to uplink them. Not a formality — it is
   global consent, and §16 carries what it exposes and the checklist to run
   first.
3. **`brokerd` side (required for storage to be readable)**: register the
   same channel name + PSK in `brokerd`'s own config. Relay of encrypted
   bytes between boards happens either way (that's a plain MQTT pub/sub
   mechanic, gated only by account ACL — see `docs/security.md` §3), but
   without this step `brokerd` can only store the channel's messages as
   opaque encrypted `raw_frames` — never as readable, queryable
   `text_messages`. Because of the raw-first storage principle
   (`docs/architecture.md` §3), adding the key later lets you reprocess
   already-stored raw frames retroactively — nothing already captured is
   lost by forgetting this step temporarily.
4. Restart `brokerd` so the new key takes effect. Hot-reload of channel
   keys without a restart is deferred for v1 (ADR-6, `docs/adr.md`) —
   plan for a brief relay interruption (drain timeout, then restart) when
   adding or rotating a channel key.

**Confirmed against real hardware**: the MQTT topic's channel segment
(`{root}/2/e/{channel}/{node}`) carries the **plain configured channel
name**, not the generated globally-unique channel ID (`name.id`,
base36-encoded, which `channel.proto`'s comments describe). `brokerd`
therefore matches `channels[].name` against that segment verbatim and never
parses it further (`docs/protocol-spec.md` §1).

**Scope limit (direct messages)**:
starting with Meshtastic firmware ≥2.5, direct messages (DMs) between two
specific nodes are encrypted with per-node PKC (public-key cryptography)
key pairs, not the shared channel PSK. `brokerd` only holds channel PSKs,
so **DM packets can never be decoded into readable text** with the design
in this document — they are stored as opaque `raw_frames` only, same as
any packet whose channel key is unknown. Only broadcast traffic on a
registered channel becomes a readable `text_messages` row. See
`docs/protocol-spec.md`'s PKC/DM subsection.

## 8. Fallback / alternate path: if a board can't (or doesn't) reach `brokerd` over its own WiFi

> **Current status for the two Heltec V4 boards**: the office WiFi has
> been confirmed to have no client isolation, so the board connecting
> directly over its own WiFi through the internet to `brokerd` is the
> default path for both. F1 below is a fallback for these two boards in
> case network policy changes later or a specific port/domain ends up
> blocked — **but F1 stops being a low-priority fallback and becomes the
> only viable path for any future WiFi-less board** (`docs/hardware.md`
> §1's market note, `docs/architecture.md` §5/§10.4). F2 remains a
> low-priority fallback either way.

### F1. MQTT client proxy over serial

- Board-side config: `mqtt.proxy_to_client_enabled = true`. The board's
  own MQTT client keeps doing everything it would do over WiFi — only
  the transport (serial instead of a WiFi radio) changes.
- This requires a serial-to-MQTT proxy tool running on the connected
  computer (`cmd/mshserial-mqtt-proxy`, not deployed yet — design
  rationale and status: `docs/architecture.md` §5, ADR-10 in
  `docs/adr.md`).
- Reference implementation: `LN4CY/mqtt-proxy` (Python) — useful for the
  serial-side wire framing.

### F2. An alternative wireless path

- Temporarily provide a dedicated SSID for the board via internet sharing
  (a hotspot) at that site.

## 9. Companion app connection target

- Connection method: choose "Network/TCP" in the app.
- Host: the board's IP, or `meshtastic.local` if there's only one board on
  the same segment.
- Port: `4403` (fixed, no change needed). **Independent of `brokerd`** — 4403
  is only ever reachable on the local WiFi band.

## 10. PlatformIO / firmware build

- Primary path: flash the official Meshtastic release binary via the web
  flasher (Chrome WebSerial) or `esptool`. No custom build is planned.
- The Heltec V4 may be in Beta support status per Meshtastic, so record the
  actual verified firmware version string in §1 once flashed (not recorded
  yet).

## 11. Non-default settings — summary

Everything below deviates from Meshtastic's own out-of-the-box defaults
(or is a `brokerd`-side default that must be deliberately flipped), listed
in one place because they're otherwise scattered across this document,
`docs/outbound-relay.md`, and `docs/brokerd-config.md`. "Stock default"
values not independently confirmed against firmware source/testing are
marked accordingly rather than guessed.

### A. Required for the core private bridge (always, regardless of any optional feature)

| Setting | Stock default | This project | Why |
|---|---|---|---|
| `network.wifi_enabled` | `false` | `true` | Required to use WiFi at all (§3) |
| `mqtt.enabled` | `false` | `true` | Required for any MQTT bridging (§7) |
| `mqtt.address` | **the official public server, pre-filled even while disabled** — stock config ships with `address: "mqtt.meshtastic.org"` and demo credentials (`username: "meshdev"`, `password: "large4cats"` — `default_mqtt_username`/`default_mqtt_password` in `src/mesh/Default.h`, copied into a fresh config by `NodeDB.cpp`); not literally blank, but the same effective trap | `<brokerd public domain>:8883` | ⚠️ **The single most consequential non-default setting in this entire document.** Leaving this at its stock value — e.g. during a rushed initial setup, or after a factory reset that wasn't followed all the way through provisioning — does not fail closed; it silently keeps the board pointed at `mqtt.meshtastic.org` (with the demo creds) instead of `brokerd`. Combined with the `pvt` channel already having `uplink_enabled = true`, this could uplink private-channel traffic (still PSK-encrypted, but with topic/`gateway_id`/timing metadata exposed) to the public server without any error being raised. **Verify this field is explicitly set to `brokerd`'s address as a step in `docs/runbook.md`'s provisioning/verification procedures, not just at initial setup.** |
| `mqtt.tls_enabled` | `false` (confirmed via `meshtastic --info` on the test board: `tlsEnabled: false` out of the box) | `true` | Required so board–`brokerd` traffic isn't sent in the clear over the public internet |
| `mqtt.encryption_enabled` | `false` | `true` — **confirmed set on both gateway boards** | ⚠️ **A name that means the opposite of what it looks like.** It does not add encryption — leaving it at the stock `false` makes the board publish every uplinked packet **decrypted**, and the official MQTT module documentation is explicit that this happens "even when your uplink channels have encryption keys set". A correct 32-byte `pvt` PSK on both boards does not protect anything on the MQTT hop while this is `false`. Combined with the `mqtt.address` trap above it is a plaintext leak to the public server. **Whose setting decides**: the *uplinking gateway's*, because it is the node doing the publishing — a non-gateway node has no MQTT connection and its own copy of this field is inert (§7's mobile-node list). So this row is a two-board question here, not a per-participant one. It also **fails silently in the healthy direction**: such a frame decodes, stores and reads exactly like a properly encrypted one, so `brokerd` reports it as `plaintext_uplinks_total` (`internal/broker.PlaintextChecker`, `docs/monitoring-api.md` §4.1) — which is the only place it is visible, and the only check that covers gateways nobody has read `--info` from |
| `mqtt.root` | `msh` | `msh/pvt` | Avoids mixing with the public convention's default namespace (§7) |
| `mqtt.username` / `mqtt.password` | blank | per-board `<PLACEHOLDER>` | Required for `brokerd`'s account/ACL model (`docs/security.md` §3) |
| `pvt` channel (doesn't exist out of the box) | — | created, with `uplink_enabled = true`, `downlink_enabled = true`, a private 32-byte PSK | This channel *is* the private bridge — nothing flows to `brokerd` without it (§7) |
| `lora.region` | unset | `KR` | Required for the radio to operate at all in-region; not project-specific, just necessary setup |
| `lora.ignore_mqtt` | **not reliably `false`** — see the note below | `false` | **A board with this `true` receives MQTT downlink and silently discards all of it.** Uplink still works, so the board looks healthy: it connects, authenticates, publishes, and its messages are stored — while nothing sent from the other site ever reaches it. Verified the hard way on the second board (see §13). |

### B. Explicitly pinned, but already matches the stock default (audit-only, not an actual behavior change)

| Setting | Stock default | This project | Why pin it anyway |
|---|---|---|---|
| Primary channel `uplink_enabled` / `downlink_enabled` | `false` (proto3 default; confirmed via `meshtastic --info`) | `false` | So the "not relayed" intent is auditable in config, not just an accident of never having been touched (§7) |
| `mqtt.json_enabled` | `false` (confirmed via `meshtastic --info`) | `false` | Prevents plaintext JSON leakage regardless of the actual stock value (§7) |

### C. Required only for the optional selective outbound relay (`docs/outbound-relay.md`)

| Setting | Required? | Stock default | This project (if feature used) | Why |
|---|---|---|---|---|
| `position.gps_mode` / `position.fixed_position` | **Required** | project sets `NOT_PRESENT` / `false` (no GPS hardware, §5) | a real position source enabled | No position source means no `POSITION_APP` packets exist at all (`docs/outbound-relay.md` §2) |
| `pvt` channel's `position_precision` | **Required** | **Corrected (was assumed `0`, confirmed otherwise)**: the *primary* channel's stock default is actually `13` (≈ 2.9km) on the test board, not `0` — a freshly created secondary channel showed `32` (full precision) instead. Either way, don't assume `0`; always set it explicitly | a coarse non-zero value in `brokerd`'s configured eligible range | This *is* the core eligibility gate — `brokerd` never truncates precision itself (`docs/outbound-relay.md` §1/§2) |
| `outbound_relay.enabled` (`brokerd`-side) | **Required** | `false` | `true` | Global kill switch; off unless deliberately turned on (ADR-12) |
| `mqtt.map_reporting_enabled` | **Required** for the map-report path | `false` (confirmed via `meshtastic --info`) | `true` — **enabled in this deployment**, and map reports do arrive at `brokerd` | `MAP_REPORT_APP` is the only payload reaching `brokerd` that carries name *and* position together, which is what meshmap's validity check needs (§14). Without it the relay has nothing map-worthy to forward. Note what it discloses — §14's "What a map report discloses" is a longer list than "a coarse position" |
| `mqtt.map_report_settings.should_report_location` | **Required** | `false` | `true` | A second, independent opt-in and a hard gate: `map_reporting_enabled` alone publishes nothing at all (§14, verified by three hours of silence). The CLI sets only the field named, so both have to be set explicitly |
| `outbound_relay.dry_run_all_rules` (`brokerd`-side) | **Required** (to actually publish) | `true` | `false`, deliberately, after review | Prevents ever publishing to the real external server by accident (`docs/outbound-relay.md` §7) |
| Primary channel's location sharing | Recommended, not required | — | explicitly disabled | Functionally, `pvt`'s own `position_precision` is what gates eligibility either way (official broadcast-selection logic already excludes Channel 0). This is a mitigation for an **unverified** firmware caveat where a secondary channel's precision might be overridden by the primary's — disabling it removes the ambiguity, but nothing structurally requires it if that caveat turns out not to apply (`docs/outbound-relay.md` §2) |
| `position.position_broadcast_smart_enabled` | **Not required at all** | `true` | `false` (this project's choice) | Affects only *how often* eligible packets arrive, not whether they're eligible — the eligibility check (§1/§4 above) is identical either way. Kept off purely for predictable, easy-to-reason-about timing; for a stationary gateway board that never moves, smart broadcast's movement-triggered extra frequency never actually triggers anyway, so in practice this barely changes behavior for *this* project regardless (`docs/outbound-relay.md` §4) |
| `boards[].node_id` (`brokerd`-side) | Conditionally required | unset | a board's real node ID | Only needed if a rule uses the stricter `origin_scope: "own_boards_only"` (`docs/brokerd-config.md`) — unused under the default `"channel_members"` |

### D. Required only for the optional serial↔MQTT proxy path (WiFi-less boards only)

| Setting | Stock default | This project (if path used) | Why |
|---|---|---|---|
| `mqtt.proxy_to_client_enabled` | `false` | `true` | Only meaningful for a board with no WiFi radio at all, or as a fallback (§8's F1) |

### E. Required only on a non-gateway node whose traffic should reach `brokerd`

| Setting | Stock default | This project (if such a node joins) | Why |
|---|---|---|---|
| `lora.config_ok_to_mqtt` | `false` (confirmed via `meshtastic --info`: `configOkToMqtt: false`) | `true`, **on that node** | A gateway uplinks its own packets unconditionally but drops another node's while this bit is clear, whatever the channel's key — so without it the node's traffic never reaches `brokerd` at all, and nothing on the gateway or in `brokerd` can grant it. It is global consent (any gateway in range, any server), so work through §16's "What enabling it exposes" and its pre-flight checklist before enabling it |

Nothing in sections C, D or E is needed for the core private bridge (section A)
to work — they're additive, optional paths.

## 12. Field-length limits (sourced)

Several config fields are shorter in practice than a first read of the
schema suggests. All of the limits below cost real debugging time during
the first board-to-`brokerd` integration test, so they are recorded with
their sources rather than left to be rediscovered.

The key fact that explains most of the confusion: **nanopb's `max_size`
includes the terminating NUL byte**, so a `max_size:N` string field holds
at most **N-1 characters**. From nanopb's own reference manual:

> `max_size`: Allocated maximum size for `bytes` and `string` fields.
> **For strings, this includes the terminating zero.**
> — nanopb's own `docs/reference.md`, not this repository's

| Field | `max_size` (`*.options`) | Usable chars | CLI-level limit | Notes |
|---|---|---|---|---|
| `ChannelSettings.name` | 12 | 11 | **10** (`--ch-add` only) | The Python CLI is *stricter* than the wire format, but **only on the `--ch-add` path**: `meshtastic/python`'s `__main__.py` has a hardcoded `if len(args.ch_add) > 10: our_exit("Warning: Channel name must be shorter. Channel not added.")`. Fails **loudly**. The `--ch-set name` path has **no** such check, so 11 characters should be reachable that way (not tested). Also reported upstream as `meshtastic/python#773`, where a maintainer confirms `ten_chars_` works and 11 does not via `--ch-add` |
| `MQTTConfig.password` | 32 | **31** | none | The CLI performs **no length validation at all** on this field (confirmed by reading `__main__.py`'s `setPref`) |
| `MQTTConfig.username` | 64 | 63 | none | Not exercised — this project's usernames are short |
| `MQTTConfig.address` | 64 | 63 | none | Not exercised |
| `MQTTConfig.root` | 32 | 31 | none | Not exercised (`msh/pvt` is 7) |

### What actually happened during the integration test

An over-length password (48, then 32 characters — the latter just one
over the 31-character limit) did **not** take effect on the board. The
board kept sending a 10-byte password, which was initially misread as
"the firmware truncates to 10 bytes."

It is not truncation: **`large4cats`, the firmware's stock default MQTT
password, is exactly 10 characters** (`src/mesh/Default.h`:
`#define default_mqtt_password "large4cats"`). The board was still
sending the stock default because the over-length value never applied.
A 10-character password then worked on the first try.

**Unverified**: whether the firmware rejects an over-length value
outright (leaving the previous/default value in place) or the `--set`
silently no-ops for another reason. Distinguishing them would need a
capture of the serial-side `--set` exchange, which was not necessary to
unblock the test. What *is* established is the 31-character ceiling and
that the stock default is what gets sent when a set does not apply.

### Practical rules

- Keep channel names to **10 characters or fewer** if you create them
  with `--ch-add` (the binding limit in practice). 11 is theoretically
  reachable via `--ch-set name`, but there is no reason to court the
  edge.
- Keep the MQTT password to **31 characters or fewer**; there is no
  warning if you exceed it, and the symptom is an authentication failure
  at the broker with the board silently still using `large4cats`.
- **If authentication fails, check whether the board is sending
  `large4cats`** before suspecting the broker: that is the fingerprint of
  "the password was never actually applied."
- With a 31-character ceiling there is still plenty of entropy available
  (31 hex chars ≈ 124 bits), so this limit does not meaningfully weaken
  `brokerd`'s account security. It is paired with bcrypt cost 12 and
  per-IP ban-after-5-failures (ADR-5) regardless.

## 13. `--info` omits zero values, so an absent setting means "default"

`meshtastic --info` prints only non-zero/non-false fields. An absent block
therefore means "all defaults", not "not configured" — five settings on these
boards were misread that way, including `lora.ignore_mqtt`, which silently
discarded all MQTT traffic on one unit while its `--info` looked identical to
the working one.

**Set every related field explicitly when provisioning** (§7's command list
does), and verify by behaviour rather than by reading `--info` back.

## 14. `mqtt.map_reporting_enabled`, and what actually gets a board on a map

Settled here from the map's **source**, not its documentation, because the
documented answer turned out to be wrong in both directions.

### Enabling it on the board does not publish to a public map

The official MQTT module docs say a node with it enabled "periodically
send[s] an unencrypted map report **to the MQTT server**" — the *configured*
one. Here that is `brokerd`. A public map only sees what reaches the
**official public server**, and `mqtt.address` is a single string with no
primary/secondary support (confirmed against the protobuf,
`docs/architecture.md` §2): a board self-reporting to the public server is a
board that has stopped bridging to `brokerd`. That is the structural reason
this project relays *from the server* instead (`docs/outbound-relay.md`,
ADR-12).

### But relaying it is the only way onto the map

meshmap.net will not display a node until it has a **name**:

Its validity check (`internal/meshtastic/node.go` in the
`brianshea2/meshmap.net` repository — AGPL-3.0, so described here rather than
quoted) rejects a node unless **all three** hold: it has been seen by at least
one uplinking gateway, its long name is a non-empty string, and its latitude
and longitude are not both zero.

`LongName` is set from exactly two payloads: `NODEINFO_APP` and
`MAP_REPORT_APP`. **Position alone is never enough**, despite the project's
README saying it shows "all position-reporting nodes" — verified by
publishing structurally-correct positions that the server accepted, real
nodes replied to, and the map still did not show
(`docs/outbound-relay.md` §10.1).

Of those two payloads, only `MAP_REPORT_APP` is reachable from `brokerd`:

| | goes where | reachable by `brokerd`? |
|---|---|---|
| `NODEINFO_APP` broadcast | the **primary** channel | no — the primary channel is deliberately never uplinked (§7) |
| `NODEINFO_APP` reply to an unknown node | the channel the unknown node was heard on | only by chance, and addressed to one node |
| `MAP_REPORT_APP` | straight to the configured broker | **yes** |

`MAP_REPORT_APP` also carries name *and* position in one packet, satisfying
all three of `IsValid`'s conditions at once.

### Board-side settings

| Key | Value | Note |
|---|---|---|
| `mqtt.map_reporting_enabled` | `true` **only if** the outbound relay is meant to publish it | Default `false`, and that stays the right default: see the disclosure list below |
| `mqtt.map_report_settings.should_report_location` | `true` | **A second, separate opt-in, and a hard gate.** `map_reporting_enabled` on its own publishes nothing at all — verified by three hours of silence with it set and this one left `false`. The protobuf comment calls it "whether we have opted-in to report our location to the map" |
| `mqtt.map_report_settings.position_precision` | 12–15 | **Coerced** into that range by the firmware ("removes obtusely large radius and privacy problematic ones from the map"); anything outside becomes the default. `0` does **not** disable it — it falls back to the default like any unset value |
| `mqtt.map_report_settings.publish_interval_secs` | `3600` minimum | Also the default. There is no way to ask for one sooner, so a wrong guess costs an hour per attempt — **except right after boot**, where the throttle is skipped (`last_report_to_map == 0`) and the first report goes out within seconds of the MQTT connection. Rebooting is the way to retest quickly |

The companion apps set these together behind one "Map reporting" toggle. The
CLI sets only the field named, which is why `--set mqtt.map_reporting_enabled
true` on its own looks like it did the job and does nothing. That pattern
recurred four times in one session on this deployment
(`lora.ignore_mqtt`, `position.gps_mode`,
`position.position_broadcast_smart_enabled`, and this one): **when
configuring by CLI, set every related field explicitly and verify with
`--get` or `--info`.** `--info` omits fields at their zero value, so an
absent block means "all defaults", not "not applicable".

Two more properties of the packet itself, confirmed from source, because a
relay has to reproduce them (`docs/outbound-relay.md` §10.1):

- it is published as the MeshPacket's **`decoded` (plaintext) variant**, even
  with `mqtt.encryption_enabled = true`
- it carries **no packet `id`** — the firmware allocates the packet zeroed
  and never sets one, so `id = 0` is normal for a map report

`brokerd`'s per-board `acl_filters` must include the map topic or the
publish is refused. The topic is `<mqtt.root>/2/map/` — with a trailing
slash — confirmed from meshmap's own subscription list
(`msh/+/2/map/` and a matching regex). With this project's `msh/pvt` root
that is `msh/pvt/2/map/`. mochi-mqtt logs ACL denials at debug level, so
without that filter the report vanishes silently
(`docs/brokerd-config.md`'s `-log-level`).

### What a map report discloses

More than a position, and unencrypted: long and short name and ID, position
and altitude, hardware model, role, firmware version, LoRa region, modem
preset, **primary channel name**, whether the node is reachable on the
default channel with a known key, and a count of locally-heard nodes. Decide
on that list, not on "it is just a coarse position"
(see "What a map report discloses" below).

## 15. `gps_mode` on a board with no GPS module

`gps_mode: ENABLED` on a board with no GPS hardware emits no positions at
all — it does not fall back to a fixed position. For a fixed installation set
`gps_mode: NOT_PRESENT` plus `--setlat/--setlon`, and leave
`position_broadcast_smart_enabled` off (it has nothing to be smart about).

## 16. A gateway uplinks another node's packet only if the sender opted in

This section is the single reference for `lora.config_ok_to_mqtt`; §7 and §11
point here rather than restating it, and `docs/runbook.md` §5.6 carries the
provisioning sequence.

### The gate

A gateway forwards its **own** packets to MQTT unconditionally, but drops
another node's unless that node set `lora.config_ok_to_mqtt`. From
`MQTT::onSend()` (firmware `v2.7.26.54e0d8d`), described rather than quoted
(the firmware is GPL-3.0 and this project is MIT — ADR-13): the packet is
dropped when **all three** hold — it did not originate on this node, the
configured MQTT server address is not private, and the packet's `Data.bitfield`
either is absent or has the "ok to MQTT" bit clear. The log line it emits names
the `DontMqttMeBro` flag.

All three hold in this deployment (the packet is another node's, the broker is
at a public address, and the flag defaults to `false`), so a non-gateway node's
traffic never arrives until the flag is set **on that node** — there is nothing
the gateway or `brokerd` can set on its behalf. The command is deliberately
not here: it belongs after "What enabling it exposes" and the checklist below.

### Why the default is `false`

It is a consent flag, and the default for consent is "no". meshtastic.org's
LoRa config page states the intent: `true` means the user approves their
packets being uplinked to MQTT brokers, `false` asks receiving nodes not to
forward them — "not a cryptographic solution but a polite request" that the
official firmware honours.

The reason it needs a default at all: a LoRa broadcast is heard by every node
in range, and any one of them may be a gateway whose stock `mqtt.address` is
the **public** `mqtt.meshtastic.org` (§11 A). With `true` as the default,
joining a mesh would silently mean publishing to the internet — and on the
primary channel, under the well-known default key, that includes `NODEINFO_APP`
(name, ID, hardware) and positions in readable form. So it fails closed, and
only those who want that exposure opt in.

The gate's other two conditions follow the same logic — each is a case where
consent already exists or nothing leaves:

| Condition for dropping | Why it is worded that way |
|---|---|
| the packet did not originate on this node | a node's own packets are always uplinked: configuring `mqtt.enabled` on it *is* the consent |
| the MQTT address is not private | a private broker is treated as the operator's own infrastructure, so the traffic never leaves their network |
| the "ok to MQTT" bit is clear | the fail-closed default above |

This project's two gateway boards are covered by the first exemption — they
uplink their own traffic and need no flag. `brokerd` sits at a public address,
so it gets no benefit from the second. That is exactly why a third,
non-gateway node is the only participant that has to opt in.

### What enabling it exposes

**Read this before deciding, not after.** Two properties make the consequences
wider than "my packets reach my broker": it is **global** (any gateway in
range, any server — it cannot be scoped to `brokerd`) and it is **a request,
not a control** (only the official firmware honours it, so a modified gateway
ignores it either way).

- **The primary channel becomes public plaintext.** It uses the well-known
  default key, so `NODEINFO_APP` (long/short name, node ID, hardware model,
  role, firmware version) and position broadcasts are readable by anyone
  subscribed to the public server.
- **A named GPS node can land on a public map.** meshmap's `IsValid` needs
  exactly what the primary channel hands out: seen by an uplinking gateway, a
  non-empty long name, and a position that is not 0/0 (§14). No map reporting
  on the node is required for this — `MAP_REPORT_APP` needs the node's own MQTT
  connection, which a non-gateway node does not have, but `NODEINFO_APP` plus a
  position over LoRa is enough.
- **Private-channel *metadata* leaks even though the payload does not.** A
  stranger's gateway uplinks the whole envelope: sender and destination node
  IDs, timing, SNR/hop data, `gateway_id`, and the **channel name** in the
  topic. Who talks to whom, how often, and which gateway heard it — and if that
  gateway publishes its own position, roughly where the node was.
- **Identity and private activity get correlated.** The same node ID appears on
  the public primary channel (with name and position) and on the private
  channel, linking the two. DM payloads stay PKC-encrypted, but sender and
  destination do not (`docs/protocol-spec.md` §3).
- **Telemetry is a behaviour log.** `DEVICE_METRICS` (battery, voltage, channel
  utilisation) broadcast on the primary channel reveals occupancy, movement and
  charging habits as a time series.
- **It is not retractable.** Third parties archive what reaches the public
  server; turning the flag off later stops new data only.

### Pre-flight checklist — then the command

1. **Silence position on the primary channel**: the stock
   `position_precision` there is `13` (≈5.8 km cells), not `0`:
   `--ch-set module_settings.position_precision 0 --ch-index 0`. On a node with
   no GPS, also confirm `gps_mode: NOT_PRESENT` and no fixed position (§15).
2. **Treat the node's name as public.** Long and short name travel in
   `NODEINFO_APP` under the default key. An empty long name also keeps the node
   off meshmap.
3. **Decide about telemetry** broadcast on the primary channel: disable it, or
   accept the time series above.
4. **Consider a custom PSK on the primary channel** — the strongest mitigation
   by far, since it makes `NODEINFO_APP`, position and telemetry unreadable to
   strangers instead of merely coarse. The cost is interoperability with the
   public mesh (`LongFast`), which a private deployment may not need.
5. **Scope it in time.** Enable it on the nodes that need it, for as long as
   they need it, and turn it off again afterwards.
6. **Never** fake a private `mqtt.address` to bypass the gate (see the last
   item under "Details" below).
7. **Verify what actually leaves.** `brokerd`'s database shows only the
   intended path; the public one has to be checked directly, by subscribing to
   the official server (`msh/+/2/e/#`) and watching for the node's own ID. This
   is the only evidence of the exposure above, in either direction.

Only then:

```
meshtastic --port <serial> --set lora.config_ok_to_mqtt true
```

### Details confirmed against the source

- **The bit is set at encode time from that node's own config**
  (`Router.cpp`, `perhapsEncode`: `has_bitfield = true; bitfield |=
  config.lora.config_ok_to_mqtt << 0`), so it reflects the sender's setting
  at the moment of transmission and nothing else.
- Position precision is **per channel** — `getPositionPrecisionForChannel()` reads the
  channel it is handed, never the primary (`PositionPrecision.cpp`). A channel
  with no `module_settings` fails closed at `0`; older firmware defaulted a
  primary channel to `32`, i.e. full precision (upstream #10509), so re-check
  after a firmware upgrade.
- Map reports are unaffected by the channel setting: they carry their own
  `map_report_settings.position_precision`.
- The setting lives in **LoRa** config, not the MQTT module, despite where
  the MQTT module documentation lists it. `MQTTConfig` has no such field.
- meshtastic.org states that channels with custom keys ignore this setting.
  The firmware source contains no such exception — the gate never reads the
  PSK. The same page's statement of *intent* is quoted above and holds; its
  statement of *scope* does not. Verify claims like this against the source at
  the tag the hardware runs.
- Do not fake a private broker address to bypass the gate:
  `isPrivateIpAddress()` counts `100.64.0.0/10` (Tailscale CGNAT), which
  would uplink **every** node's traffic in range, including packets whose
  senders explicitly marked them not-for-MQTT.

## 17. When a node's name reaches MQTT

Verified against firmware source at the tag these boards run
(`v2.7.26.54e0d8d`). It matters because the monitoring page and hook payloads
show the last name a node *stated*, and that is not the same as its current
name.

Two paths send `NODEINFO_APP`:

| Path | Destination | Channel | Reaches MQTT? |
| --- | --- | --- | --- |
| Periodic (`NodeInfoModule::runOnce`, `node_info_broadcast_secs`) | broadcast | **0**, always -- `sendOurNodeInfo` sets `p->channel` only `if (channel > 0)` and `runOnce` passes no channel | Only if channel 0 is uplinked |
| Heard a node with no user info (`MeshService.cpp`, "Heard new node on ch. %d") | that node | the channel the triggering packet arrived on | Yes, when that channel is uplinked |
| `MeshService::trySendPosition` (the per-node "ping" the app can trigger) | that node | **our own** node entry's `channel` | Only if that channel is uplinked -- and on these boards this path sends a *position*, not NodeInfo, because `hasValidPosition` is true for a fixed position |

A reply goes out on the request's channel (`MeshModule.cpp`:
`p->channel = to.channel`), so an exchange stays on the channel it started on.

Consequences observed in this deployment:

- Every NodeInfo frame ever stored here is **unicast**, none broadcast: channel 0
  has never been uplinked, so the periodic broadcast has never been seen.
- They arrived in request/reply pairs seconds apart, clustered around each
  node's provisioning -- the "heard a node with no user info" trigger fires once
  per peer and then never again, because `has_user` becomes true.
- Renaming a node does **not** produce an uplinked NodeInfo. The rename is
  announced by the periodic broadcast on channel 0.

### 17.1. What actually makes a name arrive

Waiting does not. The periodic broadcast is on channel 0 and the "heard a node
with no user info" trigger has already fired once for every peer, which is why
26 hours produced nothing.

Two paths are verified to work, and one is cheap:

1. **Make a node unknown again.** Reset one node's node database (the app's
   "Reset NodeDB"). When it next hears the others on the uplinked channel it
   sends its own `User` there with `want_response`, and their replies follow on
   the same channel. This is exactly what produced every NodeInfo frame this
   deployment has ever stored, so it is proven here. The reply may be suppressed
   for up to 12 h for a peer it heard recently
   (`USERPREFS_NODEINFO_REPLY_SUPPRESS_SECS`), but the request itself already
   carries the resetting node's own name.

2. **Enable uplink on channel 0.** Then the periodic broadcast arrives on its own
   schedule (`node_info_broadcast_secs`) and a rename shows up at the next one.
   The cost is that every other packet that node receives on the primary channel
   is uplinked and stored too -- on a default public channel that is mostly other
   people's traffic.

The app's per-node "ping" is **not** a third path on these boards: it goes
through `MeshService::trySendPosition`, which sends a position rather than
NodeInfo whenever the node has a valid position -- true here, since the position
is fixed -- and it uses our own node entry's channel index rather than the
peer's.

A node in a preferred-rebroadcaster role does not send NodeInfo on hearing a new
node (`!isPreferredRebroadcaster` in the same condition), so role changes affect
this too.

## 18. Settings not audited yet

Everything above is either measured on the hardware or read out of the firmware
source. **This section is neither.** It exists because two settings in this
document (`lora.ignore_mqtt`, §13, and `mqtt.encryption_enabled`, §11 A) were
each found late, and both share one shape: a stock default that quietly widens
exposure or narrows function while the deployment keeps looking healthy. The
list below is the result of asking which *other* settings have that shape. No
claim here about a default value or this deployment's current state has been
verified — treat each line as a question to answer on the boards, and move it
into §11 with a measurement once answered.

`--info` omits every `false`/`0` (§13), so "absent from `--info`" is not an
answer; read the field explicitly (`meshtastic --get <field>`).

| Setting | Why it could matter here | What to check |
|---|---|---|
| `device.rebroadcast_mode` | Decides whether these boards act as relay infrastructure for strangers' traffic. Not a confidentiality question (`pvt` stays encrypted) but an airtime and duty-cycle one, and it changes what a gateway *hears* and therefore what it may uplink | Current value on both boards; whether `LOCAL_ONLY`/`KNOWN_ONLY` would break the third/fourth non-gateway nodes' path to a gateway |
| `neighbor_info.enabled` | Broadcasts who-hears-whom. That graph is location inference material, and it travels on a channel other nodes may uplink | That it is off, and that nothing in the companion app turned it on per-node |
| `security.admin_key`, legacy `is_managed`, any admin channel | Remote administration is a config-write path over the mesh. §5 of `docs/security.md` covers admin *operations* but not these fields | Whether an admin key is set, and what channel remote admin would arrive on |
| `bluetooth.fixed_pin` | Stock is a well-known constant. Currently inert on both boards — BLE cannot pair while WiFi is up on ESP32 (§2) — but it becomes live for a WiFi-less board (§8's F1, ADR-10) | Value, and whether BLE is genuinely unreachable rather than merely unused |
| `store_forward` module | A node that stores and replays others' messages changes both retention and who can retrieve what, outside `brokerd`'s storage model entirely | Whether it is enabled anywhere in the mesh |
| `serial` module | An enabled serial module is a data path in and out of the node that this project's serial usage (§8, read-only debugging) does not need | Whether it is enabled |
| Telemetry broadcast | §16 lists `DEVICE_METRICS` as a behaviour log once a node opts into MQTT. Which channel it goes out on, and how often, decides how much of that is public | Per-node telemetry intervals, and the channel index each telemetry type uses |

Two of these (`device.rebroadcast_mode`, telemetry) are behaviour questions
where the answer may well be "leave it"; the rest are exposure questions where
the answer should be written down either way. Recording "checked, stock, fine"
is worth as much here as finding another `ignore_mqtt`.
