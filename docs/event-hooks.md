# Event hooks

`brokerd` can notify something outside itself when an event happens: either
by POSTing JSON to an HTTPS endpoint, or by executing a local program. Both
are off by default and both are whitelist-only.

A hook is a **notification, not a delivery guarantee** (ADR-17). The
database is the durable record; a hook that fails is counted and dropped.
Nothing here may block the broker's own path, so dispatch goes through a
bounded queue that drops its oldest entry when full (ADR-3).

## 1. Configuration

```json
"event_hooks": {
  "enabled": false,
  "dry_run": true,
  "queue_size": 256,
  "max_concurrent": 2,
  "targets": [
    {
      "name": "phone-push",
      "kind": "webhook",
      "enabled": true,
      "url_env": "BROKERD_HOOK_PHONE_URL",
      "secret_env": "BROKERD_HOOK_PHONE_SECRET",
      "timeout_seconds": 10,
      "retries": 2,
      "quiet_hours": "23:00-07:00",
      "min_interval_seconds": 60,
      "dedupe_window_seconds": 300,
      "template": "{{.BoardID}} {{.Portnum}}: {{index .Fields \"text\"}}",
      "match": {
        "events": ["frame"],
        "portnums": ["TEXT_MESSAGE_APP"],
        "channels": ["<channel name>"],
        "include_text": true,
        "exclude_own_boards": true
      }
    },
    {
      "name": "board-offline-script",
      "kind": "command",
      "enabled": true,
      "command": "/path/to/data-dir/hooks/notify.sh",
      "args": ["--source", "brokerd"],
      "timeout_seconds": 10,
      "match": { "events": ["board_connected", "board_disconnected"] }
    }
  ]
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Master switch |
| `dry_run` | **`true` when absent** | Logs what each target would receive and delivers nothing. Absent must never mean "fire for real" — the same rule as `outbound_relay.dry_run_all_rules` |
| `queue_size` | 256 | Bounded dispatch queue; a full queue drops its **oldest** entry and counts it |
| `max_concurrent` | 2 | Simultaneous deliveries and child processes |
| `targets[].kind` | — | `webhook` or `command`; required |
| `timeout_seconds` | 10 | Per attempt |
| `retries` | 2 for `webhook`, **must be 0 for `command`** | Re-running a program that may already have had an effect is worse than reporting the failure |
| `disable_after_failures` | 10 | Auto-disable the target after this many consecutive failures. In memory: a restart re-enables it. 0 disables the feature |
| `min_interval_seconds` | 0 | Rate limit per target; skipped events are counted |
| `dedupe_window_seconds` | 0 | Skip a delivery whose rendered payload is byte-identical to one sent inside this window |
| `quiet_hours` | unset | `"HH:MM-HH:MM"` in **local** time; may wrap midnight. The start minute is quiet, the end minute is not |
| `template` | unset | Renders the event as text or as the receiver's own JSON (§4) |
| `headers` | none | Extra request headers for a webhook. A value written `${VAR}` is resolved from the environment at load, so a header carrying a credential still keeps it out of `config.json` |
| `allow_unsigned` | `false` | Permits a non-loopback webhook with no `secret_env`. Required for receivers that authenticate by the URL itself; an absent secret alone never means "send anyway" |

## 2. Events

| Event | Source | Notes |
| --- | --- | --- |
| `frame` | storage worker | Fires after the frame and its decoded rows are written, and only for a frame that decoded. A duplicate delivery (ADR-14) never fires |
| `board_connected` | presence hook | |
| `board_disconnected` | presence hook | `reason` is one of: `server shutting down` (brokerd is stopping — every restart produces one per connected board), `clean` (the board disconnected gracefully), or the transport error, which is the difference that matters when diagnosing a flaky uplink. mochi-mqtt reports the read error in all three cases, so brokerd labels its own shutdown before closing anything; without that, a restart looks like a fault |

**A restart produces four events** with two boards: two `board_disconnected`
with `reason: server shutting down`, then two `board_connected` once they
reconnect. That is truthful — the sessions really did end — so an alerting
target should filter on the reason, or use `min_interval_seconds`, rather than
expecting silence.

Shutdown events are delivered, not dropped: the dispatcher outlives the broker
during shutdown for exactly this reason, shutdown then waits up to 15 s for
queued and in-flight deliveries to finish, and anything still queued after that
is logged as `events left undelivered at shutdown` rather than disappearing.

Both halves were needed. Queuing the events without waiting for them meant the
first real shutdown killed its own hook commands mid-run and logged
`context canceled` and `signal: killed` — a queued event whose delivery is
killed is a more confusing failure than one that was never queued.

`match.events` **defaults to `["frame"]`**. A target written to notify about
messages must not silently start receiving connection events because a later
version added them.

## 3. Payload

```json
{
  "event": "frame",
  "delivered_at": "2026-01-01T00:00:00Z",
  "received_at": "2026-01-01T00:00:00Z",
  "board_id": "alpha",
  "gateway_id": "!11223344",
  "topic": "msh/pvt/2/e/<channel>/!11223344",
  "channel": "<channel>",
  "packet_id": "0x5674c7f4",
  "from": "0x99aabbcc",
  "from_id": "!11223344",
  "from_name": "Alpha Node (ALFA)",
  "from_long_name": "Alpha Node",
  "from_short_name": "ALFA",
  "to": "0xffffffff",
  "portnum": "TEXT_MESSAGE_APP",
  "rx_snr": 6,
  "hop_limit": 3,
  "hop_start": 3,
  "fields": { "text": "…" }
}
```

**A field the frame did not state is absent, not zero** — the same rule the
database follows (ADR-15). A consumer must not be able to read a missing
`rx_rssi` as 0 dBm, nor a missing `packet_id` as the identity `0x00000000`:
`MAP_REPORT_APP` states no packet id at all, which is the fact duplicate
suppression depends on (ADR-14).

`hop_limit` and `via_mqtt` are the exceptions and are always present once the
packet parsed, because for them protobuf's default *is* the meaningful value
(no hops left; not relayed over MQTT).

**A name and an id are separate fields, on purpose.** `from_name` is the sender
as a reader knows it -- the long name with the short name after it, since the
short name is what the node's own screen shows -- and `from_id` is the node id
spelled Meshtastic's way. A single combined string hid the short name and made
the id look like part of the name.

`from_id` is present whenever `from` is. `from_name` is **absent** for a node
that has never introduced itself, so name the sender with

```
{{or .FromName .FromID}}
```

which needs no conditional and never renders an empty string. Interpolating
`from_long_name` directly does, and it also drops the short name.

`from` keeps the `0x` form it has always had: `from_id` is for reading, `from`
is for parsing.

`from_long_name`, `from_short_name` and `to_long_name` come from what a node has
said about itself in a `NODEINFO_APP` frame (`docs/storage-schema.md` §9), not
from the frame being delivered. **They are absent for a node that has never
broadcast one** — never the id in their place, so a consumer can tell "no name
learnt" from a name. `to_long_name` is also absent when the destination is the
sender or a broadcast.

`delivered_at` is the moment brokerd produced the payload, not the moment it
was sent: a retry re-sends the same bytes, and a timestamp that moved between
attempts would make one event look like two.

Two fields are opt-in per target:

- `match.include_text` — without it, `fields.text` is stripped. The message
  body is the one field whose exposure to a third party cannot be undone, so
  it requires saying so explicitly. A `template` cannot reach around this.
- `match.include_raw_payload` — adds the decrypted `Data.payload` as base64,
  for a consumer that decodes portnums itself.

`webhook` deliveries carry:

| Header | Value |
| --- | --- |
| `X-Brokerd-Signature` | `sha256=<HMAC-SHA256 of the exact body>` using `secret_env` |
| `X-Brokerd-Delivery` | a per-delivery id, so a receiver can tell a retry from a second event |

A `secret_env` is **required** for any non-loopback webhook, and the URL
must be `https` unless it is loopback. Both are checked when the config
loads, so a typo fails at startup rather than at the moment the event it was
meant to report happens.

### 3.1. Every value a template can use

**A template names Go fields, not the JSON keys above.** The payload calls it
`board_id`; a template must say `{{.BoardID}}`. Getting this wrong used to parse
fine and fail when the first matching event arrived; brokerd now renders every
template against sample events at startup and refuses to start instead.

| In a template | In the JSON payload | Present |
| --- | --- | --- |
| `{{.Event}}` | `event` | always (`frame`, `board_connected`, `board_disconnected`) |
| `{{.DeliveredAt}}` | `delivered_at` | always, RFC 3339 UTC |
| `{{.ReceivedAt}}` | `received_at` | frame events |
| `{{.BoardID}}` | `board_id` | always |
| `{{.GatewayID}}` | `gateway_id` | frame events |
| `{{.Topic}}` | `topic` | frame events |
| `{{.Channel}}` | `channel` | frame events |
| `{{.PacketID}}` | `packet_id` | when the packet stated one -- `MAP_REPORT_APP` does not |
| `{{.FromID}}` / `{{.ToID}}` | `from_id` / `to_id` | when the packet parsed; `!hex` |
| `{{.FromName}}` / `{{.ToName}}` | `from_name` / `to_name` | when that node has introduced itself; `Long (SHORT)` |
| `{{.FromLongName}}` / `{{.FromShortName}}` | `from_long_name` / `from_short_name` | same, unformatted |
| `{{.FromNode}}` / `{{.ToNode}}` | `from` / `to` | when the packet parsed; `0x…` for parsing |
| `{{.Portnum}}` | `portnum` | frame events |
| `{{.RxSnr}}` `{{.RxRssi}}` `{{.HopStart}}` `{{.Bitfield}}` | same | only when the frame stated them |
| `{{.HopLimit}}` `{{.ViaMqtt}}` | same | whenever the packet parsed |
| `{{index .Fields "…"}}` | `fields.…` | see §3.2; needs `include_text` for `text` |
| `{{.RawPayload}}` | `raw_payload` | only with `include_raw_payload`; base64 |
| `{{.Reason}}` | `reason` | board events |

Name the sender with `{{or .FromName .FromID}}`: that is a name when one is
known and the id when none is, with no conditional and never an empty string.

### 3.2. What `fields` contains, by portnum

`fields` is the decoded payload. Absent keys mean the frame did not state them.

| Portnum | Keys |
| --- | --- |
| `TEXT_MESSAGE_APP` | `text` (only with `match.include_text`) |
| `POSITION_APP` | `latitude_i`, `longitude_i` (1e-7 degrees, integers), `precision_bits`, `has_fix` |
| `NODEINFO_APP` | `id`, `long_name`, `short_name`, `hw_model`, `role`, `is_licensed`, `is_unmessagable`, `has_public_key` |
| `TELEMETRY_APP` | `time`, `device_metrics` (a nested object), `other_variants_present` |
| `ROUTING_APP` | `error_reason`, `route_request_present`, `route_reply_present` |
| `MAP_REPORT_APP` | position keys as above, plus whatever the report states |

A key that is absent renders as nothing with `{{index .Fields "x"}}`, so guard it
when its absence should read differently:

```
{{if index .Fields "text"}}{{index .Fields "text"}}{{else}}(no text){{end}}
```

## 4. Templates

`template` renders the event as text — what a chat bot or a `logger` call
wants, rather than a JSON object:

```
"template": "{{.BoardID}} {{.Portnum}}: {{index .Fields \"text\"}}"
```

Go `text/template`, over the same event struct the JSON form carries,
**after** the opt-in fields have been applied. Syntax is checked at startup.
`text/template` rather than `html/template` deliberately: the output goes
into a chat message or a program's stdin, where HTML escaping would corrupt
it — so do not feed the result into a web page without escaping it there.

Three traps, all of them things brokerd now catches at startup or that a test
pins:

1. **JSON keys are not field names.** `{{.board_id}}` is a startup failure, not
   an empty string; write `{{.BoardID}}` (§3.1).
2. **An absent measurement prints `<nil>`.** `{{.RxSnr}}` on a frame that stated
   no SNR renders the text `<nil>`. Use `{{json .RxSnr}}` (which gives `null`) or
   guard it with `{{if .RxSnr}}`.
3. **`text/template` does no escaping.** Building JSON needs `json` around every
   interpolated value (§4.1).

Two functions are available:

| Function | Purpose |
| --- | --- |
| `json` | Marshals a value to a JSON literal, quotes and all |
| `trunc N` | Cuts a value to N **runes** and appends `…`, so a truncated non-ASCII message does not arrive as mojibake |

### 4.1. Building a receiver's own JSON body

Many chat services accept an "incoming webhook" whose body is their own JSON
shape. Build it with `json` around every interpolated value — **never with
bare `{{.Field}}`**. A mesh message is arbitrary text from whoever is in
radio range, and one quote or newline would otherwise turn the notification
into a rejected request:

```json
"template": "{\"body\": {{json (index .Fields \"text\")}}, \"connectColor\": \"#2196F3\", \"connectInfo\": [{\"title\": \"from\", \"description\": {{json .FromNode}}}]}"
```

Such a receiver usually needs two more things, both configurable per target:

- a vendor-specific `Accept` header — `headers` covers it;
- no signature, because the URL *is* the credential — `allow_unsigned: true`
  says so explicitly, and the URL belongs in `url_env` like any other secret.

Watch the receiver's own rate limits: a service permitting, say, 60 requests
a minute is far above this project's traffic (a few frames an hour), but
`min_interval_seconds` is the guard if a chatty portnum is ever matched.

## 5. `kind: command` — what brokerd guarantees

This is an execution path, so its rules are stricter than the rest of
`brokerd`, where permission problems are reported and left alone
(`docs/security.md` §4). Here a bad permission **refuses to load**.

| Rule | Why |
| --- | --- |
| No shell — the program is executed directly with its `argv`, never through `sh -c` | Nothing in an event can be interpreted as syntax |
| The payload arrives on **stdin**, never in an argument | A message body in a command line would land in `ps` output and audit logs, and would invite a quoting bug in every hook script written against this |
| The child gets `PATH` and `BROKERD_HOOK=1`, **not brokerd's environment** | brokerd's environment holds channel PSKs, the monitoring token and the DNS provider's API token. A child inheriting it would hand all of that to a hook script |
| `command` must be an absolute path, a regular file, executable, and **not writable by group or other** | Anyone who can write that file decides what brokerd executes. Resolving through `PATH` would make it depend on the environment brokerd happened to inherit |
| Timeout kills the whole process group | A stalled grandchild cannot hold a worker slot forever |
| Whatever the script prints to **stdout is logged by brokerd** (truncated to 512 bytes) | Inside the sandbox a script can write only to the data directory and cannot count on reaching journald itself, so `echo` has to be the whole reporting mechanism. Discarding stdout left a script with nowhere to report to |
| `retries` must be 0 | See the table in §1 |

The child also inherits the systemd sandbox, so with the shipped unit
(`ProtectHome=read-only`, `ProtectSystem=strict`) **the only writable place
for a hook script is the data directory**. A script that logs to `$HOME` will
fail, quietly from the script's point of view.

The minimal environment has a practical consequence worth stating: the child's
`PATH` is `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` and
nothing else, so an interpreter installed under a version manager (asdf, pyenv,
nvm) is **not** reachable. Use what is in `/usr/bin`, or an absolute path.

A hook script does not need to keep anything. Every frame is already in the
database, which is the durable record (ADR-17); a script that also appends to
its own file creates a second copy of message plaintext, with its own
retention and rotation to manage. Printing one line is usually the whole job:

```sh
#!/bin/sh
set -eu
jq -r '[.event, (if .board_id then "board=" + .board_id else empty end),
        (if .fields.text then "text=" + (.fields.text|tostring) else empty end)]
       | join(" ")'
```

## 6. Checking the plumbing

Before anything is sent, `-check-config` reports what each target would receive
and renders its template against sample events, so a template naming a JSON key
instead of a field (§3.1) fails there rather than at the first real event:

```bash
mesh-brokerd -config config.json -check-config
```


```sh
mesh-brokerd -config <path> -test-hooks
```

Delivers one synthetic event per event kind to every enabled target, prints
the resulting counters and exits non-zero if any delivery failed. It runs
before TLS and storage are touched, so it needs neither a certificate nor a
writable database — and it respects `dry_run`, since a self-test that
ignored it would be the one thing that fires a hook nobody armed.

## 7. Counters

`GET /api/v1/stats/messages` carries an `event_hooks` object
(`docs/monitoring-api.md` §4.1): `fired_total`, `failed_total`,
`dropped_total`, `ratelimited_total`, `suppressed_total`, `dry_run_total`
and `disabled_targets`, all per target name.

An empty object means no hooks are configured, which is deliberately
distinguishable from hooks that never fired.

`disabled_targets` is the only place `brokerd` reports an action it took on
its own initiative, so it must be readable after the log line has scrolled
away.
