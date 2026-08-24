# Environment — what to record for a deployment

A template. This project is one operator's deployment; the values below are
deliberately left as placeholders so the file can be published. Fill in a
private copy if you want a record, and keep real identifiers out of the
repository.

## Sites

| Site | Role | Notes to record |
| --- | --- | --- |
| `<site A>` | Gateway board + admin machine | WiFi SSID handling, whether client isolation is on, whether outbound 8883 is reachable |
| `<site B>` | Gateway board | Same, plus who rotates the WiFi password and how often |

## `brokerd` server

| Item | Value to record |
| --- | --- |
| Host | `<provider / spec / arch>` — anything with a public address and a stable DNS name |
| OS, Go version | `<...>` — `CGO_ENABLED=1` is required (`internal/storage`) |
| DNS | One A record for the broker hostname. Keep it **DNS-only** if behind a CDN: MQTT over TLS on 8883 is not HTTP and cannot be proxied |
| Ports | 8883 inbound (MQTT/TLS). The monitoring API binds loopback only |
| Data directory | Holds `config.json`, `.env`, the SQLite database and `tls-cache/`. One directory to back up and lock down; the checkout stays disposable |
| Service | `systemd` unit from `deploy/`, `Restart=always`, journald output |

## Boards

Record per board: model, firmware version, role, whether it has GPS, fixed
position or not, and its MQTT username. Node IDs and long names are
deliberately **not** recorded here.

Settings that are not obvious and have cost time on real hardware are
documented in `docs/firmware-config.md`, not duplicated here — in particular
`lora.ignore_mqtt` (§13), `gps_mode` on a board without GPS (§15), and
`lora.config_ok_to_mqtt` for any non-gateway node whose traffic should reach
the broker (§16).

## Connection stability

Expect this to differ **by site, not by board**: identical firmware and
settings produced dozens of read timeouts a day at one site and none at the
other. `listener.keepalive_floor_seconds` raises the read deadline and turns a
short stall into a non-event; the root cause is usually the network, not the
board.

## Measured volume (this deployment, as an order of magnitude)

Useful only for sizing retention:

| Measurement | Value |
| --- | --- |
| Steady-state rate | ~4 frames/hour for two gateways plus one occasional node |
| Mean stored payload | ~100 bytes |
| Database after 3 days | ~60 KB |
| Extrapolated 30-day retention | ~3,000 frames, ~300 KB of payload |

At that scale retention defaults cost nothing and pre-deletion backup tooling
is unnecessary (ADR-7).
