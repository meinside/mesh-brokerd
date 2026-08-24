# `brokerd` Configuration Reference

Complete `config.json` key reference for `brokerd`. This is the structural
config file (`docs/security.md` §7's split: secrets → environment
variables, structure → `config.json`). Only `config.json.sample` (with
`<PLACEHOLDER>` values) is ever committed — a real `config.json` is
listed in `.gitignore`.

**Naming convention for `*_env` keys.** Derive the variable name from the
thing it belongs to, uppercased: a board `alpha` uses
`BROKERD_BOARD_ALPHA_PASSWORD_HASH`, a channel `PrvtChn` uses
`BROKERD_CHANNEL_PRVTCHN_PSK`. Nothing enforces this — the name is just a
string — but a variable whose name cannot be predicted from the config is one
more thing to look up when a deployment has several boards or channels.
`config.json.sample` and `.env.sample` follow it and are kept in step by
`internal/config`'s sample smoke test, which loads the sample through the real
loader and fails if a referenced variable is missing.

`outbound_relay.targets[].password_env` is deliberately *not* derived from the
target id: its value is a published constant for the public server
(`docs/outbound-relay.md` §6.1), so the name describes what it is rather than
which target happens to use it.

Secrets referenced from this file (account passwords, channel PSKs, the
monitoring API token, a DNS provider token for ADR-8) are **not** stored
here as values — this file stores the **name** of the environment
variable that holds each secret, per `docs/security.md` §7.

## Command-line flags

Everything configurable lives in `config.json`; the flags only say where to
find it and how loudly to log.

| Flag | Default | Purpose |
|---|---|---|
| `-config` | `config.json` | path to this file |
| `-reprocess` | off | `dry-run` re-decodes every stored frame and reports what would change; `apply` writes it, after copying the database with `VACUUM INTO` first. Any other value is an error, so a typo cannot rewrite every row (`docs/storage-schema.md` §7). Runs before TLS and the broker start |
| `-test-hooks` | off | Delivers one synthetic event per event kind to every enabled event hook, prints the counters and exits non-zero if any delivery failed (`docs/event-hooks.md` §6). Runs before TLS and storage, so it needs neither a certificate nor a writable database, and it respects `dry_run` |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error`. An unrecognised value **aborts startup** rather than falling back, so a typo cannot silently leave logging at a level nobody chose |

`-log-level debug` exists for one failure in particular. mochi-mqtt logs
ACL denials at debug, so a board publishing outside its `acl_filters` —
typically a wrong `mqtt.root` on the board — authenticates normally and then
has every publish discarded with **nothing logged at `info`**. Raising the
level surfaces `failed allowed ACL check`. It changes only the level, not
the log format, so existing log consumers keep working
(`docs/runbook.md` §8).

## Top-level shape

```json
{
  "listener": {
    "mqtt_addr": ":8883",
    "tls_cert_domains": ["<broker.example.com>"],
    "tls_dns_provider": "cloudflare",
    "tls_cache_dir": "/var/lib/brokerd/tls-cache",
    "tls_use_staging_ca": false
  },
  "boards": [
    {
      "id": "alpha",
      "username": "alpha",
      "password_hash_env": "BROKERD_BOARD_ALPHA_PASSWORD_HASH",
      "acl_filters": ["msh/pvt/2/e/#"]
    },
    {
      "id": "bravo",
      "username": "bravo",
      "password_hash_env": "BROKERD_BOARD_BRAVO_PASSWORD_HASH",
      "acl_filters": ["msh/pvt/2/e/#"]
    }
  ],
  "channels": [
    { "name": "pvt", "psk_env": "BROKERD_CHANNEL_PVT_PSK" }
  ],
  "retention": {
    "raw_frames_days": 30,
    "decoded_days": 30
  },
  "auth": {
    "bcrypt_cost": 12,
    "failure_threshold": 5,
    "ban_duration_minutes": 30,
    "ip_allowlist": []
  },
  "monitoring": {
    "listen_addr": "127.0.0.1:9101",
    "api_token_env": "BROKERD_MONITORING_TOKEN"
  },
  "storage": {
    "path": "/var/lib/brokerd/brokerd.db"
  }
}
```

## Key reference

| Key | Type | Default | Notes |
|---|---|---|---|
| `listener.mqtt_addr` | string | `:8883` | mochi-mqtt's TCP+TLS listen address. |
| `listener.tls_cert_domains` | []string | — (required) | Domains the certificate manager requests a certificate for (ADR-8). |
| `listener.tls_dns_provider` | string | — (required) | A `go-acme/lego` DNS-01 provider name from `internal/tlscert/providers.go`'s registry (e.g. `"cloudflare"`). The provider reads its own credentials from its conventional environment variable (e.g. Cloudflare's `CLOUDFLARE_DNS_API_TOKEN`) — never from this file, and not via a `*_env` indirection either, since lego providers each expect a fixed env var name they choose. See https://go-acme.github.io/lego/dns/ for the provider's required variables. |
| `listener.tls_cache_dir` | string | — (required) | Where the ACME account key/registration and the obtained certificate are persisted across restarts, so a restart never re-issues a certificate (avoids Let's Encrypt rate limits). Parent directory must exist and be writable by the `brokerd` service user, like `storage.path`. |
| `listener.tls_use_staging_ca` | bool | `false` | Switches to Let's Encrypt's staging directory (looser rate limits, certificates not trusted by real clients) — use to verify the DNS-01 flow end-to-end before pointing at production. |
| `listener.keepalive_floor_seconds` | int | `0` | Raises a client's advertised MQTT keepalive to at least this many seconds, which lengthens mochi-mqtt's read deadline (`keepalive * 1.5`, [MQTT-3.1.2-22]). `0` leaves every client's value alone and only logs it — the way to measure before picking a floor. Meshtastic firmware configures no keepalive and inherits PubSubClient's **15 s**, giving a 22-second deadline in which a single missed PING ends the session; one deployed board reconnected 55 times in a day on a flaky network while an identically-configured one on a stable network never did. Raising the floor does not make a network reliable — it stops a short stall from costing a TLS handshake, a re-auth, and every message published while disconnected. Out-of-range values are rejected rather than truncated. |
| `boards[].id` | string | — (required) | Free-form site/board identifier (`docs/architecture.md` §10.1) — never validated against an enum. |
| `boards[].username` | string | — (required) | MQTT username; matches the board's `mqtt.username` (`docs/firmware-config.md` §7). |
| `boards[].password_hash_env` | string | — (required) | Env var name holding the **bcrypt hash** (not plaintext) compared in the custom `OnConnectAuthenticate` hook (`docs/security.md` §3). |
| `boards[].acl_filters` | []string | — (required) | Ledger ACL filter(s) this account may read/write. Today, every board shares `msh/pvt/2/e/#` (`docs/security.md` §3's caveat). | **A board publishing map reports needs the map topic listed too**: it is `<mqtt.root>/2/map/` (trailing slash), which no `.../2/e/#` filter matches. Without it the publish is refused and mochi-mqtt logs the denial at debug level only, so the report vanishes silently (`-log-level`, `docs/firmware-config.md` §14).
| `boards[].node_id` | string | — (optional) | The board's own Meshtastic node ID, entered in the same `!hex` form the CLI/app display it in (e.g. `!4a2d2b38` — obtain via `meshtastic --host <IP> --info`, the `user.id` field of that board's own entry under "Nodes in mesh"; see `docs/runbook.md` for the general lookup procedure). Used **only** by `outbound_relay` rules with `origin_scope: "own_boards_only"` (`docs/outbound-relay.md` §3) to tell "this board's own position" apart from "a packet this board merely gatewayed from another node on the same private channel." Required if this board is ever listed in such a rule; unused otherwise. **Representation note**: `raw_frames.from_node` (`docs/storage-schema.md` §1) stores the decimal node number, not the `!hex` string — `internal/config` parses `node_id`'s hex form to decimal once at load time, so the comparison at match time is a plain integer equality, not a string/format conversion done per-packet. How `brokerd` cross-checks the configured value against the node ID actually seen in traffic is `internal/broker.NodeIDChecker`, reported as `board_node_id_mismatches_total`. |
| `channels[].name` | string | — (required) | Channel name as configured on the boards (`docs/firmware-config.md` §7). Matched against the topic's `{channel}` segment verbatim (`docs/protocol-spec.md` §1). |
| `channels[].psk_env` | string | — (required) | Env var name holding the channel's 32-byte PSK, **standard base64 (with padding)** — matching Meshtastic's own convention (the app UI, CLI `--ch-set psk base64:{key}`, and QR/share URLs all represent the PSK as base64, e.g. the default channel's `AQ==`). Copy the value directly from the app/CLI with no re-encoding (ADR-11, `docs/adr.md`). |
| `retention.raw_frames_days` | int | `30` | Days to keep `raw_frames`. **Omitting the key gives 30, not unlimited** — unbounded growth and an indefinite record of traffic is the wrong thing to get by accident. Write `0` explicitly for unlimited. Negative values are rejected at load. ADR-7, `docs/storage-schema.md` §6. |
| `retention.decoded_days` | int | `30` | Days to keep decoded rows (`text_messages`). Same defaulting rules as `raw_frames_days` above. ADR-7, `docs/storage-schema.md` §6. |
| `auth.bcrypt_cost` | int | `12` | ADR-5. **Advisory only, and `brokerd` never reads it at runtime**: bcrypt stores its cost inside each hash, so verification uses the cost the hash was *created* with and cannot be influenced by config. The key records the cost this deployment intends, and `cmd/brokerd-keygen -cost` is what actually applies it. Changing it here re-hashes nothing — to raise the cost, regenerate the hashes. |
| `auth.failure_threshold` | int | `5` | ADR-5. |
| `auth.ban_duration_minutes` | int | `30` | ADR-5. |
| `auth.ip_allowlist` | []string | `[]` | IPs/CIDRs exempt from the failure-threshold ban (e.g. a management network, `docs/security.md` §4) — empty means no exemptions. |
| `monitoring.listen_addr` | string | `127.0.0.1:9101` | Where the read-only monitoring API listens. **Defaults to loopback on purpose**: the API is meant to be published by a reverse proxy, not by `brokerd` (`docs/monitoring-api.md` §0, templates in `deploy/nginx/`). A loopback default means forgetting to configure this leaves the API unreachable from the internet rather than exposed on it, and `brokerd` never needs a privileged-port capability. Set an externally-reachable address only if you intend `brokerd` to face the internet directly. |
| `monitoring.api_token_env` | string | — (required) | Env var name holding the token for `docs/monitoring-api.md` §2. A browser sends it as an HTTP Basic **password** (any username); a program sends `Authorization: Bearer`. |
| `monitoring.trust_tailscale_identity` | bool | `false` | Accept a `Tailscale-User-Login` header instead of the token for the HTML page (`docs/monitoring-api.md` §2.2). **Startup fails if this is on and `listen_addr` is not loopback**: the header is only trustworthy while the local proxy is the sole caller. Nothing about it is Tailscale-specific except the header name. |
| `monitoring.tailscale_allowed_logins` | []string | `[]` | Restricts which logins that path accepts. Empty means any tailnet user who can reach the proxy — including someone the tailnet was shared with. |
| `storage.path` | string | — (required) | SQLite file path. Parent directory must exist and be writable by the `brokerd` service user. |
| `outbound_relay.*` | object | see `docs/outbound-relay.md` §3 | Selective, publish-only relay of whitelisted data to an external target (ADR-12, implemented in `internal/relay`). Not shown in the top-level shape example above — full schema, defaults (`enabled: false`, `dry_run: true`), board-side prerequisites, and validation notes live in `docs/outbound-relay.md` §2/§3 rather than duplicated here. `targets[].psk` is a plain string (not `*_env`-indirected, unlike every other secret in this file) because v1 only accepts the literal sentinel `"default"` — Meshtastic's well-known, non-secret public-channel key (`internal/decode.DefaultChannelPSK`); any other value is a startup error. `rules[].eligibility.min_precision_bits`/`max_precision_bits` default to `10`/`16` — matching the official public server's own location-precision filter exactly. | Target brokers take optional `username`/`password_env` credentials; the official public server **requires** them (`docs/outbound-relay.md` §6.1). Rules' `source_portnum` accepts `POSITION_APP`, `NODEINFO_APP` and `MAP_REPORT_APP` only (`docs/outbound-relay.md` §10).
| `event_hooks.*` | object | see `docs/event-hooks.md` §1 | Notifying something outside `brokerd` when an event happens: an HTTPS POST or a local program (ADR-17, implemented in `internal/hook`). Defaults are `enabled: false` and **`dry_run: true` when the key is absent**, since absent must never mean "fire for real". `retries` must be `0` for a `command` target. A `command` must be an absolute path and, when the target is enabled, a regular file that is executable and not writable by group or other — otherwise startup fails; this is the one place `brokerd` refuses rather than reports. `quiet_hours` is `"HH:MM-HH:MM"` in **local** time and may wrap midnight. |

## Validation rules (implementation requirement)

- `brokerd` must refuse to start (fail fast, not silently run
  unauthenticated) if any `*_env` key names an environment variable that
  is unset or empty.
- Every `boards[].id` and `channels[].name` must be unique within the
  file; duplicates are a startup error, not a "last one wins" merge.
- `acl_filters` entries are validated to be inside `mqtt.root`'s namespace
  (`msh/pvt/...`) at startup — a config accidentally granting `#` is
  rejected rather than silently accepted.
- `event_hooks` is validated as far as it can be without the machine's own
  state: kinds, event names, `quiet_hours` syntax, template syntax, board
  references and the shape of a `command` path are checked for **every**
  target, enabled or not. The filesystem check on a `command` and the
  resolution of a webhook's `url_env`/`secret_env` apply only to an
  **enabled** target — a shipped sample names paths and secrets that do not
  exist on the machine reading it, and refusing to start over a hook nobody
  armed would be the wrong trade. Turning a target on moves both checks to
  that startup.
- Every `channels[].psk_env` value must base64-decode to exactly 32 bytes;
  a decode error or wrong length is a startup error (ADR-11), not a
  warning — the same fail-fast rule as unset `*_env` variables above.

## Checking a config file

```bash
mesh-brokerd -config /path/to/config.json -check-config
```

Loads the file, resolves every `*_env` secret, renders every hook template, and
prints what the config would do -- then exits. Nothing listens, no certificate is
requested, no database is opened and no hook is delivered.

The report states what is **enabled** and what each hook target would receive,
because a file is more often valid-but-inert than invalid: a target left
`enabled: false`, or filtered to a portnum this mesh never sends, matches nothing
and says nothing.

**An undefined key is an error, not a comment.** `json.Unmarshal` ignores one
silently, so `min_intervl_seconds` used to leave the rate limit unset while the
file appeared to set it. JSON has no comments, so a config file cannot carry
notes; keep them next to the file instead.
