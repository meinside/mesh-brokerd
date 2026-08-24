# mesh-brokerd

> A personal, private Meshtastic messaging network — bridging office and
> home boards over MQTT, and securely relaying/storing every message
> through a self-hosted server (`brokerd`).

A project that places two Meshtastic®-supported, WiFi + MQTT-capable boards
(currently Heltec V4 units, ESP32-S3 based, no GPS module — see
`docs/hardware.md` for the general board requirement set and why the
architecture doesn't depend on this specific model) at
an office and a home, logically connects the two sites via Meshtastic
firmware + MQTT, and durably stores messages with `brokerd` (a single Go
process that unifies broker + storage + monitoring).

## Connectivity model (at a glance)

| Path | Used by | Protocol/Port |
|---|---|---|
| WiFi TCP | Companion app | TCP 4403 |
| WiFi MQTT | The board itself (firmware) | `brokerd`'s public address (TLS) |
| Bluetooth (BLE) | Companion app | BLE (only path for a WiFi-less board) |
| USB Serial | Optional tooling, or the *only* bridge path for a WiFi-less board | Meshtastic Serial API |

Full connectivity model, including the WiFi-less-board serial↔MQTT proxy
path: `docs/architecture.md` §6.

- **Both currently deployed boards operate on WiFi alone** (power can come
  from a wall USB-C adapter or a computer — it doesn't matter — and both
  MQTT and the companion app are handled over WiFi). A future WiFi-less
  board would instead use the serial proxy path above; see
  `docs/hardware.md` for why the architecture supports either.
- **`brokerd` is the core of the system** — it unifies the MQTT broker
  (mochi-mqtt embedded) + message storage (SQLite) + monitoring/statistics
  into a single Go process.
- **`brokerd` is deployed on a publicly reachable Linux server** and is not
  tied to any specific hosting method (Tailscale, a home lab, etc.). If the
  user already operates a public server, that becomes the default path; a
  guide for running it from a home lab (RPi5) instead is also kept in
  `docs/deployment.md`.
- **The USB-C serial connection is kept as an optional extension point** —
  it is not required for the core data flow, but whenever a board happens to
  be connected to a computer at either site, it can be used for real-time
  inspection, debugging, a future dashboard app, etc.
- The Meshtastic firmware only allows a single server to be configured in
  `mqtt.address` (confirmed against the protobuf definition), so **broker
  redundancy/failover cannot be implemented via board configuration** —
  `brokerd` is structurally a single point of failure. See
  `docs/architecture.md` for details and mitigations.
- The decision to expose `brokerd` publicly, and the strong authentication
  that follows from it (accounts/ACL/TLS/monitoring, including the custom
  hooks required because of the mochi-mqtt embed), is recorded as an ADR in
  `docs/security.md`.

## Document index

- [`docs/architecture.md`](docs/architecture.md) — Overall architecture, `brokerd` design, the serial extension point, data flow, firmware constraints
- [`docs/deployment.md`](docs/deployment.md) — `brokerd` hosting guide (public server as the default path, plus a home-lab alternative)
- [`docs/firmware-config.md`](docs/firmware-config.md) — Per-board Meshtastic settings, Bluetooth/WiFi/MQTT behavior, flashing procedure
- [`docs/runbook.md`](docs/runbook.md) — Companion app connection procedure, the protocol capture spike, `brokerd` verification, strong-auth operations, troubleshooting
- [`docs/security.md`](docs/security.md) — Public-exposure ADR, TLS limitations, strong-auth layers (including mochi-mqtt custom hooks), trust boundaries
- [`docs/hardware.md`](docs/hardware.md) — General board requirements plus the current hardware instance's (Heltec V4) specs and Meshtastic support status
- [`docs/environment.md`](docs/environment.md) — A template for recording a deployment's own sites, networks and measured volume
- [`docs/protocol-spec.md`](docs/protocol-spec.md) — MQTT topic grammar, envelope layering, crypto/nonce spec, portnum decoder registry — what `internal/decode` is written against
- [`docs/storage-schema.md`](docs/storage-schema.md) — SQLite DDL, indexes, retention/VACUUM, backup, reprocessing — what `internal/storage` is written against
- [`docs/monitoring-api.md`](docs/monitoring-api.md) — The read-only monitoring API's exposure model (loopback + reverse proxy), endpoints, auth, and counter definitions
- [`docs/brokerd-config.md`](docs/brokerd-config.md) — Complete `config.json` key reference
- [`docs/adr.md`](docs/adr.md) — Implementation-level ADR index (storage/relay isolation, decrypt-failure handling, auth-hook parameters, channel-key reload, retention, TLS ownership, PSK encoding, selective outbound relay, deduplication, event hooks, no migration runner)
- [`docs/outbound-relay.md`](docs/outbound-relay.md) — Optional feature: `brokerd`'s selective, publish-only relay of whitelisted data (position-first) to the official public MQTT server
- [`docs/event-hooks.md`](docs/event-hooks.md) — Optional feature: notifying something outside `brokerd` when an event happens, by webhook POST or by running a local program

## Status

Implemented and running against real hardware: two gateway boards at two
sites bridge over MQTT/TLS, messages are decrypted and stored, cross-site
delivery is verified in both directions, and a third non-gateway LoRa node's
traffic reaches the broker through a gateway.

The selective outbound relay to the official public MQTT server is
implemented and off by default (`docs/outbound-relay.md`).

Not implemented: `cmd/mshserial-mqtt-proxy`, needed only for a board with no
WiFi of its own (ADR-10).


## Running it

```bash
go install github.com/meinside/mesh-brokerd@latest   # CGO_ENABLED=1
cp config.json.sample config.json                          # then edit
cp .env.sample .env                                        # then fill in

set -a; . ./.env; set +a                                   # see note below
mesh-brokerd -check-config -config ./config.json     # what it would do
mesh-brokerd -config ./config.json
```

`brokerd` reads secrets from its **environment**, not from `.env` — it never
parses that file. Under systemd the unit's `EnvironmentFile=` supplies them
(`deploy/mesh-brokerd.service`); by hand, source the file as above.
Nothing starts with a secret missing: the config names each variable and
startup fails naming the one that is unset.

`-check-config` loads the config, resolves every `*_env` secret, renders each
event-hook template against a sample event and prints what is enabled — every
board, channel, relay rule and hook target — without opening a listener, a
database or the network. A config is more often valid but inert than invalid,
so this reports what *would* happen rather than only whether it parses.

Two files are needed and neither belongs in version control: `config.json`
(structure, ports, rules) and the secrets it names indirectly, which are read
from the environment (`.env.sample` lists every variable). Key references:

- `docs/brokerd-config.md` — every `config.json` key
- `docs/deployment.md` + `deploy/` — systemd unit, reverse proxy, TLS
- `docs/firmware-config.md` — the per-board Meshtastic settings this expects
- `docs/runbook.md` — verification and troubleshooting procedures

## Repository layout

```
main.go                 the primary binary: installs as `mesh-brokerd`,
                        referred to as `brokerd` throughout the docs
internal/               all supporting packages (deliberately not importable)
  decode/               topic grammar, wire format, crypto, portnum decoders
  config/               config.json + env-sourced secrets
  storage/              SQLite schema, writes, retention, dedup
  auth/                 bcrypt auth hook + per-IP banning
  broker/               mochi-mqtt wiring + storage worker
  monitor/              read-only HTTP monitoring API
  relay/                selective outbound relay
  tlscert/              ACME DNS-01 certificate management
cmd/                    secondary tools, each a separate binary
  brokerd-keygen/       generates bcrypt account hashes and channel PSKs
deploy/                 systemd unit template
docs/                   architecture, decisions, and operational procedures
testdata/               real captured protocol fixtures
```

The primary binary lives in the module root rather than under `cmd/`,
following the "command with supporting packages" layout in
[Organizing a Go module](https://go.dev/doc/modules/layout): the root
declares `package main` and everything else lives in `internal/`. So it
installs in one step:

```bash
go install github.com/meinside/mesh-brokerd@latest
```

`make build` produces the same name (`bin/mesh-brokerd`), so the
artifact is called the same thing however it was built. Secondary tools
get their own directory under `cmd/`.

## Quality gates

`make check` runs `gofmt`, `go vet`, `golangci-lint`, and `go test ./...`;
every change must pass it, and CI enforces the same target
(`.github/workflows/check.yml`). **`CGO_ENABLED=1` is required** because
`internal/storage` uses `mattn/go-sqlite3` (a cgo binding); the `Makefile`
exports it.

Every test in `make check` runs with no secret and no network access.
Tests needing either are isolated behind build tags and excluded:
`tls_e2e` (real ACME + live DNS round trip), `diag` (reads a live `brokerd`
database) and `hardware` (needs physical boards and someone watching them).
CI type-checks all three so they cannot rot unnoticed. No test is ever gated on a secret being present: one that
fails or skips because an environment variable is unset is worse than no
test, so ground truth that needs no key is committed instead.

## License

MIT — see [`LICENSE`](LICENSE). Deliberately kept independent of
`meshtastic/protobufs` (GPL-3.0, no linking exception) — this project
never vendors or generates code from their `.proto` files; see ADR-13 in
`docs/adr.md`. The same rule applies to the documentation: upstream
behaviour is described, never quoted as source, so `docs/` carries no
verbatim code from copyleft projects either.

## Trademark

Meshtastic® is a registered trademark of Meshtastic LLC. Meshtastic software
components are released under various licenses, see
[GitHub](https://github.com/meshtastic) for details. No warranty is provided -
use at your own risk.

This project is not affiliated with or endorsed by the Meshtastic project. It
is named `mesh-brokerd` precisely so that its own name carries no Meshtastic
trademark; every mention of Meshtastic in this repository refers to that
project's own software and hardware.
