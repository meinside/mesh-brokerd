# Architecture

## 1. Goal

Two Meshtastic-supported boards with WiFi + an MQTT-capable gateway
module are placed at two sites (office and home) more than 5–10 km apart,
running the official Meshtastic firmware (latest stable), such that:

1. Both boards connect to MQTT over **WiFi** to exchange messages with each
   other (a logical mesh), and also support **WiFi/TCP (4403)** connections
   from the companion app.
2. Message exchange and storage are handled by a **single Go process,
   `brokerd`**. `brokerd` unifies an MQTT broker (mochi-mqtt embedded),
   message storage, and monitoring/statistics into one process.
3. `brokerd` is deployed on a **publicly reachable Linux server** (a VPS or
   any public server the user operates). It is not tied to a specific
   hosting method (Tailscale, a home lab, etc.); concrete deployment options
   are covered in `docs/deployment.md`.
4. **USB-C serial is kept as an optional extension point, not a
   requirement.** Whenever a board happens to be connected to a computer
   (e.g. a Mac) via USB-C, that computer can use the serial connection for
   real-time inspection, debugging, a future dashboard app, etc.
5. Stored data is text-message-centric for now, but the design should be
   extensible to telemetry, position, etc.

## 2. Why an MQTT bridge instead of a physical LoRa mesh

Since the office–home distance is 5–10+ km in an urban environment, a direct
LoRa link over SX1262 is effectively impossible (practical range in urban
NLOS conditions is typically a few hundred meters to 1.5 km, and without a
relay node in between, no link forms at all). Connecting the two sites via
a **logical mesh over MQTT** is therefore the only realistic approach.

Meshtastic firmware provides an **MQTT Gateway module** for exactly this:

- A node with `uplink_enabled=true` on a channel wraps packets it receives
  locally in a `ServiceEnvelope` protobuf and publishes them to the MQTT
  broker.
- A remote node with `downlink_enabled=true` on the same channel subscribes
  to that topic and **rebroadcasts** received packets onto its own local
  mesh.
- Firmware-level duplicate suppression via `gateway_id` + packet ID prevents
  loops.

**Requirements for this to work**: both boards must share ① the same
`mqtt.root`, ② the same channel name + the same PSK, ③ the same
`lora.region`/`modem_preset`, and ④ `uplink_enabled=true` +
`downlink_enabled=true`.

⑤ applies only to packets a gateway **did not originate**: the sending node
must have set `lora.config_ok_to_mqtt` (default `false`), or the gateway
silently declines to uplink them. This is per-sender consent, so it costs
nothing between the two gateways — each uplinks its own traffic — but it is
the whole story for any third node on the mesh (`docs/firmware-config.md`
§16).

**Firmware constraint (important)**: Meshtastic's
`ModuleConfig.MQTTConfig.address` is a **single string field** (confirmed
directly against `module_config.proto` in `meshtastic/protobufs`). There is
no primary/secondary redundancy field in the protobuf at all. In other
words, **broker redundancy/failover cannot be implemented through board
configuration.** If redundancy is ever needed, it has to be solved at the
server-infrastructure level (e.g. DNS failover), not via board config — and
this is exactly why `brokerd` is structurally a single point of failure
(see §7).

## 3. `brokerd`: broker + storage + monitoring, unified

### Why a single process

- Splitting the broker (e.g. mosquitto) and storage (a separate process)
  was considered first, following the classic fault-isolation principle: a
  bug in the storage logic would not also take down the broker.
- However, to reduce operational burden (two systemd units, two sets of
  config, two log sources) and to keep the whole stack in Go, the decision
  was made to **embed mochi-mqtt (a Go-native, embeddable MQTT broker
  library) in the same process as the storage/monitoring logic.**
- **Trade-off accepted**: a serious bug (e.g. a panic) in the storage/
  decoding logic can now also kill the broker itself, interrupting
  cross-site message relay. This has a larger blast radius than a
  split-process design. This risk is accepted deliberately; storage/
  decoding code must absorb panics via `recover()` so a bug there does not
  take down the whole process (a hard requirement at implementation time).
- Rationale for trusting mochi-mqtt itself: it explicitly passes the
  official Eclipse Paho Interoperability Tests (v5 and v3), has over a
  thousand unit test scenarios, and ships frequent (weekly) releases. Being
  written in Go also structurally avoids a whole class of memory-safety
  bugs common to C-based brokers. That said, it has a shorter track record
  and a smaller maintainer pool than mosquitto (15+ years, an Eclipse
  Foundation project, automatically patched via distro security updates) —
  this is accepted as a known risk.

### `brokerd`'s responsibilities

1. **MQTT broker** (mochi-mqtt embedded): a TCP listener on `8883` with
   TLS (the standard port used throughout this project, `docs/deployment.md`)
   relaying uplink/downlink traffic between the two boards. Plaintext
   `1883` is only the firmware's own fallback when `mqtt.tls_enabled=false`
   (used for the home-lab LAN special case, `docs/deployment.md`) — it is
   not the default and is not opened on the public listener.
2. **Authentication/ACL**: built on mochi-mqtt's `hooks/auth` **Auth
   Ledger** for per-account access rules. However, the Ledger compares
   **passwords in plaintext** (confirmed from source, see
   `docs/security.md`), so a custom `OnConnectAuthenticate` hook that
   compares password hashes is written instead. mochi-mqtt also has no
   built-in automatic banning after repeated auth failures, so that is
   implemented as a custom hook as well.

   **Hook order matters here.** mochi-mqtt dispatches
   `OnConnectAuthenticate` to each hook in registration order and stops
   at the first that returns true, so `brokerd`'s bcrypt hook is
   registered *before* the Ledger hook — the Ledger cannot
   authenticate (it holds no usable password material) and logs
   "client failed authentication check" whenever it is consulted, which
   would otherwise appear on every *successful* connection.

   A third connection-level hook records the MQTT keepalive each
   client asks for and can raise it to a floor, because the read
   deadline mochi-mqtt derives from it (`keepalive * 1.5`) is short
   enough on Meshtastic's default to end a session on one missed PING
   (`docs/environment.md`, `listener.keepalive_floor_seconds`).

3. **Storage**: an event hook (e.g. `OnPublish`) intercepts
   `ServiceEnvelope`s passing through the broker, decrypts them with the
   channel PSK, and stores them in SQLite. The "preserve the raw frame
   first" principle is kept — the original bytes are always stored before
   any normalization. The retention period is configurable per table (see
   §9), not hard-coded. Full schema: `docs/storage-schema.md`; topic/
   envelope/crypto details the hook relies on: `docs/protocol-spec.md`;
   how the hook is kept off the broker's own failure path: ADR-3/ADR-4 in
   `docs/adr.md`.
4. **Monitoring/statistics** (a new, strengthened requirement): built on
   mochi-mqtt's built-in `$SYS` dashboard (HTTP) and
   `listeners.NewHTTPHealthCheck`, plus `brokerd`-specific extras
   (implemented in `internal/monitor`, `docs/monitoring-api.md`):
   - Per-site node online/offline status and last-seen time
   - Message throughput (per second/day) and per-topic statistics
   - Authentication success/failure counters (for security monitoring)
   - A simple HTTP API or dashboard page to query the above, exposed
     read-only, bound to `127.0.0.1` and published via a reverse proxy
     (`docs/monitoring-api.md` §0). Any endpoint that can change `brokerd`'s
     configuration is kept off public ports entirely (SSH tunnel / IP
     allowlist only, see `docs/security.md` §4 and `docs/deployment.md`).
     Full endpoint/response/auth spec: `docs/monitoring-api.md`.

## 4. Deployment: a public Linux server, not tied to any specific hosting method

- `brokerd` is deployed on a **Linux server with a public domain/IP** —
  a VPS, a server the user already operates publicly, or an exposed home
  lab; the architecture is designed not to depend on any one of these.
- Requirements that hold regardless of hosting method: a public domain,
  TLS (via a standard method such as Let's Encrypt/`certbot`), a firewall
  that opens only the necessary ports, and strong authentication (§3).
- **Tailscale is no longer a required part of the core architecture.**
  Earlier designs used Tailscale Funnel (limited to ports 443/8443/10000, a
  beta feature, bandwidth-limited) as the default way to expose a home lab
  (an RPi5). If a user already has a public server they can operate, a
  standard deployment there is more proven and has fewer constraints.
- Concrete deployment paths (a public VPS as the default, plus a guide for
  exposing a home lab) are covered in **`docs/deployment.md`**.
- The two boards are, in principle, **symmetric**: both connect over their
  own WiFi, through the internet, to `brokerd`'s public address. (If
  `brokerd` is run from a home lab instead, the board at that site can
  connect over the local LAN directly — see the home-lab guide in
  `docs/deployment.md`.)

## 5. USB-C serial: an extension point, now with a concrete first use case

- Both boards can be powered via USB-C regardless of what's on the other
  end (a wall adapter or a computer). **Whenever a board is connected to a
  computer, the serial client API is also available.**
- This serial connection is **not required for the two currently deployed
  boards** (both have WiFi and connect to `brokerd` directly, §6's "WiFi
  MQTT" path) — but it stops being purely optional/hypothetical for a
  board that has **no WiFi at all**, which is an increasingly common
  profile among newer Meshtastic hardware (`docs/hardware.md` §1's market
  note). For such a board, serial is the *only* path to bridge it into
  `brokerd` at all.
- **Planned tool: a serial↔MQTT proxy CLI** (working name
  `cmd/mshserial-mqtt-proxy`; separate binary from `brokerd`, per
  the two-binary rule — no shared `internal/*` package
  dependency). Design (ADR-10, `docs/adr.md`, amended after checking
  the official protobuf schema):
  - The board sets `mqtt.proxy_to_client_enabled = true`
    (`docs/firmware-config.md` §8's F1). This does **not** open a
    TCP/TLS socket on the board — the board still builds and encrypts
    the `ServiceEnvelope` with the channel PSK, then hands the
    resulting `topic` + opaque bytes to whatever's connected over the
    **Phone API** (the same protocol/framing the companion app uses,
    here: serial) as a `MqttClientProxyMessage` inside a `FromRadio`
    message. Downlink works the same way in reverse via `ToRadio`.
  - The CLI is a **real MQTT client**: it reads the board's own
    `mqtt.address`/`username`/`password` from its module config over
    the Phone API, uses those to open its own connection to `brokerd`'s
    `8883` listener (terminating TLS itself — there is no board-side
    TLS session to preserve, since the board never opens one in this
    mode), and relays `MqttClientProxyMessage`s bidirectionally. It
    still never parses a `ServiceEnvelope` or touches a channel PSK —
    the channel-encrypted payload stays opaque, exactly as originally
    intended — but it does hold the board's real account password,
    unlike the original "dumb byte relay" design assumed.
  - Needs the computer running it to have its own internet access, and
    to run the CLI continuously for as long as that board needs to stay
    bridged (§7's new failure mode below).
  - The remaining implementation work is the Phone API's serial framing
    and a `ToRadio`/`FromRadio`/`AdminMessage` subset, not open protocol
    questions.
- Other example uses of the serial extension point (unaffected by the
  above, still optional):
  - Local real-time inspection/debugging
  - A future real-time status dashboard app
  - Supplementary local backup (optional)
- Serial port exclusivity: only one process can hold the port open at a
  time — the proxy CLI and any other serial tool (debugging, etc.)
  cannot run against the same board concurrently (`docs/runbook.md` §6).

## 6. Connectivity model (summary)

| Path | Used by | Protocol/Port | Notes |
|---|---|---|---|
| WiFi TCP | Companion app | TCP 4403 | Only for boards with WiFi. Identical on boards at both sites today |
| WiFi MQTT | The board itself (firmware) | `brokerd`'s public address (TLS) | Cross-site message bridge for boards with WiFi; hosting method is covered in `docs/deployment.md` |
| USB Serial (MQTT proxy) | `MqttClientProxyMessage`s relayed by the planned `cmd/mshserial-mqtt-proxy` CLI (§5), which itself connects to `brokerd`'s `8883` listener as a real MQTT client | Meshtastic Serial (Phone) API framing, carrying `MqttClientProxyMessage`s — not a raw TCP/TLS tunnel | **Required** (not just optional) for a board with no WiFi at all; requires a permanently attached, internet-connected computer running the CLI |
| USB Serial (other tooling) | (Optional) debugging/dashboard tooling | Meshtastic Serial API | Not required for the core data flow; an extension point, mutually exclusive with the row above (port exclusivity) |
| Bluetooth (BLE) | Companion app | BLE | For boards with WiFi: automatically disabled while WiFi is on (ESP32-specific, `docs/hardware.md` §1). For a board with **no WiFi at all**, BLE is the companion app's *only* path — TCP 4403 has nothing to connect to |

> Official documentation quote: "ESP32 Devices: Bluetooth will be disabled
> if WiFi is enabled. The WiFi setting takes precedence." —
> meshtastic.org/docs/configuration/radio/bluetooth
>
> This is an **ESP32-specific** fact, not a Meshtastic-wide guarantee —
> see `docs/hardware.md` §1's caveats. It applies to the currently
> deployed Heltec V4 boards; a differently-chipset board might not share
> this limitation, and a board with no WiFi radio at all makes the
> question moot (BLE is simply the only option).

### Data flow (ASCII, default public-server path, WiFi-equipped boards)

```
[Companion app] --WiFi/TCP:4403--> [Board (office)]
                                        |
                                        |  WiFi (office network) -> Internet (TLS)
                                        v
                          [brokerd @ public Linux server]
                     (mochi-mqtt broker + storage + monitoring, single process)
                                        ^
                                        |  WiFi (home network) -> Internet (TLS)
                                  [Board (home)] <--WiFi/TCP:4403-- [Companion app]

(optional, at either site) [Board] <--USB-C (power + serial, optional)--> [Computer: future tooling]
```

### Data flow (ASCII, a WiFi-less board via the serial↔MQTT proxy, §5)

```
[Companion app] --BLE--> [Board, no WiFi radio]
                              |
                              |  USB-C serial (mqtt.proxy_to_client_enabled=true)
                              v
                 [Computer: cmd/mshserial-mqtt-proxy]
                 (real MQTT client; reads mqtt.username/password from
                  the board; channel payload stays opaque, ADR-10)
                              |
                              |  TCP/TLS :8883 over the computer's own internet connection
                              v
                [brokerd @ public Linux server]
```

## 7. Failure modes

- **Companion app unreachable when WiFi is down**: if WiFi drops, the
  companion app cannot connect over TCP, and it does not fall back to BLE
  automatically unless WiFi is explicitly turned off.
- **`brokerd` server outage (defined behavior)**: if `brokerd` dies, the
  broker, storage, and monitoring all stop together. **`brokerd` is the
  system's single point of failure**, and as established in §2, the
  firmware has no way to configure a secondary server, so there is no
  board-side workaround.
  - Cross-site message relay stops completely. With no broker to queue
    anything, messages sent during this window never reach the other site.
  - Each site's companion app keeps working locally (it operates on the
    local WiFi band, or over BLE for a WiFi-less board — §6), but
    messages won't be delivered to the remote site.
  - **Messages lost during the outage cannot be recovered retroactively**
    once service resumes. Auto-restart (`systemd Restart=always`) only
    guarantees "back to normal from this point on" — it does not prevent
    the loss itself.
  - Mitigations (UPS/health checks/alerts, DNS failover if ever needed) are
    listed in §8.
- **A board disconnected from MQTT loses whatever was published meanwhile.**
  The firmware publishes at QoS 0 (its MQTT library supports no higher) and
  connects with `cleanSession`, so a broker has nothing to retain for an
  absent subscriber. `brokerd` still stores such frames — the record stays
  complete while the delivery does not. The firmware's own 16-packet queue
  covers **uplink** only. See §8.1; the magnitude is counted rather than assumed.
- **A node keeps no message history.** It holds one bounded RAM queue for its
  phone (`MAX_RX_TOPHONE`, 32 on ESP32-S3), lost on reboot, and the first
  Phone-API client to connect **dequeues** it — the `meshtastic` CLI included.
  So "the app shows nothing" says nothing about delivery: connect the app
  before running CLI commands, and treat `text_messages` as the only durable
  record.
- **`brokerd`'s blast radius**: a bug in the storage/decoding logic can
  take down the broker core as well (§3). This is mitigated with
  `recover()`-based defenses, unit tests, and raw-frame-first storage, but
  the structural risk remains. The concrete mitigation design (bounded
  queue between the relay path and the storage worker, drop-and-count on
  overflow, `recover()` at the worker's top level and per-message) is
  recorded as ADR-3 in `docs/adr.md`.
- **Decryption failures**: an incorrect channel key/nonce calculation can
  silently store corrupted data. Mitigated by raw-frame-first storage plus
  unit tests; the concrete failure-handling behavior (always store the raw
  frame, structured log line without key material, counter exposed via
  monitoring) is recorded as ADR-4 in `docs/adr.md`.
- **Serial contention** (if a serial tool is actually built): multiple
  processes cannot open the same port at once.
- **New per-site single point of failure for a WiFi-less board using the
  serial↔MQTT proxy (§5)**: unlike a WiFi-equipped board, whose only
  dependency for bridging is its own WiFi + `brokerd`, a WiFi-less board's
  bridging depends on **three** things staying up simultaneously: the
  board itself, the companion computer, and the
  `cmd/mshserial-mqtt-proxy` process on it. If the computer is off,
  crashes, or its own internet drops, that site's cross-site relay stops
  exactly as if `brokerd` itself were down — even though `brokerd` and
  the other site are fine. This is a strictly worse availability profile
  than a WiFi-equipped board, and is the direct operational cost of using
  a WiFi-less board at all (`docs/hardware.md` §1's market note). Treat
  the proxy computer the same way as `brokerd` for `systemd
  Restart=always` + health-check purposes if this path is ever adopted.

## 8. Future mitigations for `brokerd` outages (optional, later)

### 8.1 Downlink loss while a board is offline

The loss mechanism is in §7 (QoS 0 + `cleanSession`), neither changeable from
the broker side. Options considered:

| Option | Why it was not adopted |
| --- | --- |
| **Retained messages** — publish a retained copy per topic so a reconnecting board gets it immediately | MQTT retains only the **last** message per topic, and every frame on a channel shares one topic, so this stores one message and loses the rest. Worse, it is re-delivered on *every* reconnect (dozens a day), and the board would re-inject a stale packet into RF each time |
| **Persistent sessions / QoS 1** — the standard MQTT answer | Requires the *client* to ask for them. The firmware hardcodes `cleanSession` and cannot publish above QoS 0 (§7); a broker cannot opt a client in |
| **Broker-side replay queue** — hold frames a board missed and publish them on reconnect | Technically possible (mochi-mqtt exposes connect/disconnect hooks and an inline publish path that bypasses ACL). But it replays *old* traffic into a live RF mesh: the receiving node rebroadcasts it and the phone shows it as new, minutes or hours late. It needs a TTL, a per-board cap, suppression of the board's own frames, and interacts with duplicate detection on both sides (ADR-14 here, `wasSeenRecently` there). That is a lot of machinery to build before knowing whether anything is actually being lost |
| **A site agent holding a durable session** — a small always-on client per site that subscribes with a persistent session and injects into the local mesh over the Phone API (TCP 4403) | The most correct answer, and it moves the reliability boundary onto hardware this project controls. It is also a new component per site, one site has no such hardware, and it overlaps with `cmd/mshserial-mqtt-proxy` (ADR-10). Worth revisiting if measurement shows real loss |
| **Reduce disconnections** | Already done as far as this project can: `listener.keepalive_floor_seconds` lengthens the read deadline. The root cause is on a network this project does not control |

**Decision: quantify before building.** `brokerd` counts frames published
while a subscribing board was absent (`downlink_missed_total`,
`connected_boards` — `internal/broker.PresenceHook`). At ~4 frames/hour with
reconnects lasting seconds the loss may be zero, in which case none of the
above is worth its risk.

## 9. Data retention policy

Actual message/telemetry volume is not yet known, so a fixed retention
period is not hard-coded.

- `brokerd` exposes two separate retention settings, each in days, `0`
  meaning unlimited:
  - `retention.raw_frames_days` — how long `raw_frames` rows are kept.
    Start at `0` (unlimited), since raw frames are also the input to any
    future reprocessing (`docs/firmware-config.md` §7's checklist).
  - `retention.decoded_days` — how long normalized/decoded rows (e.g.
    `text_messages`) are kept. Can be tuned independently, typically
    shorter, once real query patterns are known.
  - Full key reference: `docs/brokerd-config.md`; full DDL and deletion
    queries: `docs/storage-schema.md`.
- Deletion is a hard delete (for storage management). Whether to back up
  before deleting is a separate operational decision (ADR-7 in `docs/adr.md`).

## 10. Extension strategy

Two different axes, with different scope. Both "adopted" items are
implemented; the deferred one is deferred on purpose.

**10.1 More boards and sites in one mesh (adopted).** Adding a board means an
MQTT account with its own bcrypt hash and ACL filter, plus the channel key in
`brokerd`'s config. Nothing in the broker, decoder or storage is per-board.
Boards owned by *other people* would additionally need per-account topic
scoping, which today's shared filter does not provide.

**10.2 Federation with external brokers.**

- *Full bidirectional federation* — subscribing to another broker and merging
  its traffic — stays **deferred**. It would import trust decisions (whose
  packets, which keys, what loop suppression) that this project has no reason
  to make yet. If it is ever added, echo suppression keyed on
  `(topic, packet_id)` is a prerequisite.
- *Selective outbound relay* to the official public server is **adopted** and
  implemented (`docs/outbound-relay.md`, ADR-12). It is one-way, rule-based,
  and whitelist-only: the decision is "publish this specific already-coarse
  payload", not "connect two meshes".

**10.3 Other extension points.** A serial↔MQTT proxy for a board with no WiFi
(ADR-10, unimplemented), and additional decoders per portnum, which are
additive to `internal/decode`'s registry.

**10.4 Other board hardware (adopted).** The bridge depends only on a board
that speaks Meshtastic MQTT over TCP/TLS and can reach the internet — not on
any specific model. Model-specific facts (BLE/WiFi mutual exclusivity on
ESP32, USB-UART drivers, GPS presence) belong to `docs/hardware.md` and
`docs/firmware-config.md`, so mixed hardware across sites needs no
architectural change. The WiFi requirement has two satisfying paths: the
board's own WiFi, or the serial proxy above.

