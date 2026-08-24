# Monitoring API

Spec for `brokerd`'s read-only monitoring surface. Nothing described here
can change `brokerd`'s configuration — anything that can is kept off
public ports entirely per `docs/security.md` §4.

## 0. How it is exposed

`brokerd` binds this API to **`127.0.0.1` only** by default
(`monitoring.listen_addr`, `docs/brokerd-config.md`) and does **not**
expose it publicly itself. Publishing it is a reverse-proxy job:

```
browser --HTTPS--> Cloudflare (proxied, terminates TLS)
        --HTTP---> nginx :80
        --HTTP---> 127.0.0.1:9101  (brokerd)
```

The site template is `deploy/nginx/monitoring-site.conf.sample`; the
reasoning and install steps are in `docs/deployment.md`. Hardening the
nginx instance itself is server-wide configuration and out of scope for
this repository.

Why not bind `:443` directly, as earlier revisions of this document
specified:

- Binding a privileged port needed `CAP_NET_BIND_SERVICE` on the service;
  a loopback bind needs no capabilities at all.
- A loopback bind means the API is **structurally** unreachable from the
  internet except through the proxy, rather than relying on the bearer
  token as the only barrier.
- TLS for this surface becomes the proxy's problem, so `brokerd`'s own
  ACME certificate (ADR-8) is needed only for the `8883` MQTT listener.

**Trade-off accepted (deliberate, and specific to this deployment):** the
Cloudflare→origin hop is plaintext HTTP ("Flexible" mode), so the bearer
token and the IP addresses returned by `/api/v1/stats/auth` traverse one
intermediate network in the clear. This was weighed against the
alternative of a Cloudflare Origin Certificate and accepted because the
exposed data is read-only metadata — never message content, channel PSKs,
or any ability to change configuration. Cloudflare and the hosting
provider see plaintext in *every* Cloudflare mode, so Flexible adds
roughly one hop's worth of exposure. The mitigation that does matter is
restricting nginx to Cloudflare's ranges, without which anyone knowing the
origin IP could reach this API directly over plaintext and bypass
Cloudflare's protections entirely.

## 1. Endpoints

| Method | Path | Response | Notes |
|---|---|---|---|
| GET | `/health` | `200 OK`, body `{"status":"ok"}` | Unauthenticated — used by external uptime checks (`docs/architecture.md` §8) and `systemd`/load-balancer health probes. Carries no sensitive information. |
| GET | `/` | HTML page (§5) | The only endpoint that offers a Basic challenge, so a browser prompts instead of showing a bare 401. Authenticated |
| GET | `/api/v1/nodes` | `[{"board_id":"alpha","last_seen":"2025-01-01T00:00:00Z","status":"online"}, ...]` | Per-board (not yet per-mesh-node — that needs `NODEINFO_APP` decoding, `docs/protocol-spec.md` §4) online/offline + last-seen. Authenticated. |
| GET | `/api/v1/stats/messages` | `{"throughput_per_topic":{...},"decode_failures_by_reason":{...},"storage_queue_drops":0,"outbound_relay":{...},"listener_noise_suppressed_total":{...},"board_node_id_mismatches_total":{...},"acl_denials_total":{...},"downlink_missed_total":{...},"session_takeovers_total":{...},"connected_boards":[...]}` | Backs ADR-3's drop counter, ADR-4's decode-failure counters, ADR-12's outbound-relay counters (`docs/outbound-relay.md` §8), and the report-only counters of §4.1. Authenticated. |
| GET | `/api/v1/stats/auth` | `{"auth_failures_total":0,"active_bans":[{"ip":"...","expires_at":"..."}]}` | Backs ADR-5. **IP addresses are visible here** — this endpoint is authenticated, not exposed anonymously. |
| GET | `/metrics` | Prometheus exposition format | Optional/deferred (`docs/architecture.md` §10.3) — listed here so the path is reserved and doesn't collide with a future ad-hoc endpoint. |

All authenticated endpoints share one auth mechanism (§2). None of them
accept any method other than `GET`, and none take a body.

## 2. Authentication

One secret: the token from `monitoring.api_token_env`. It can be presented
in two ways, because a program and a browser cannot present it the same way.

| Caller | How |
| --- | --- |
| A program (`curl`, a script, a dashboard) | `Authorization: Bearer <token>` |
| A **browser** | HTTP Basic, with the token as the **password** and any username. The HTML page answers an unauthenticated request with a `WWW-Authenticate: Basic` challenge, so the browser prompts |

Basic exists because a browser cannot set a header by typing a URL. The
alternatives were considered and rejected:

- **`?token=` in the URL** — lands in server logs, browser history and
  `Referer` headers. No amount of documentation stops it from being pasted
  somewhere.
- **A login form and a session cookie** — new state, a logout story, and CSRF
  questions, in exchange for a nicer prompt.

Anything else is refused with `401`, and **every refusal is logged with a
reason** — `no_credential`, `bad_token`, `no_identity_header`,
`identity_not_on_allowlist`, `identity_header_present_but_trust_disabled` or
`funnel_request` — along with whether an identity header arrived and the
`X-Forwarded-For` address that connected. The same reason is shown on the 401
page itself. Without that, four different misconfigurations produce an
identical blank 401 and neither side of the connection has any evidence.

The 401 body is HTML rather than a line of text because **not every browser
offers a Basic prompt**: this was observed behind a Tailscale Serve proxy,
where the `WWW-Authenticate` header arrived intact and no prompt appeared. The
header is still sent, so a browser that does prompt still prompts.

There is no session and no cookie.

### 2.1. Reaching the page from a browser, four ways

The listener binds loopback by default (§0), so the question is only who may
reach it. All four work; none requires the others.

| Path | Browser sends | Notes |
| --- | --- | --- |
| **SSH tunnel** — `ssh -L 9101:127.0.0.1:9101 <host>`, then `http://127.0.0.1:9101/` | the token, via the Basic prompt | Nothing is exposed. Works with no extra software on the server |
| **Reverse proxy that injects the header** — `proxy_set_header Authorization "Bearer <token>";` (`deploy/nginx/monitoring-site.conf.sample`) | nothing | The browser never learns the token; the proxy must then do its own authentication (basic auth, mTLS, an identity provider), because anyone who reaches it is authenticated to `brokerd` |
| **Reverse proxy without injection** | the token, via the Basic prompt | The proxy terminates TLS and forwards `Authorization` unchanged |
| **A private overlay network** (e.g. Tailscale Serve, §2.2) | nothing, if identity trust is enabled | The network is the perimeter |

### 2.2. Trusting an identity header instead of the token

`monitoring.trust_tailscale_identity` (default **false**) lets the page
authenticate a request by a `Tailscale-User-Login` header instead of the
token, optionally restricted with `monitoring.tailscale_allowed_logins`.

This is sound only under conditions that Tailscale's own documentation
states, and `brokerd` enforces what it can:

- Tailscale Serve **injects** that header and **strips** any copy the client
  supplied, so it cannot be spoofed *through the proxy*.
- Tailscale Funnel — which is public — does **not** inject it. A missing
  header is always refused, so exposing this port with Funnel by mistake
  yields a locked page rather than a public one.
- Requests from **tagged devices** carry no identity, and are refused for
  the same reason: a tagged host is not a person.
- The header is only meaningful while nothing but the local proxy can reach
  the listener. `brokerd` therefore **refuses to start** if this option is
  on and `monitoring.listen_addr` is not loopback.

### 2.3. Mounting the page on a sub-path

The page can live under a prefix rather than at the root — e.g.
`https://<host>/brokerd/` — with any proxy that strips the prefix before
forwarding:

```sh
tailscale serve --bg --set-path=/brokerd 9101      # remove: same flags plus `off`
```

`brokerd` needs no configuration for this, and that is not luck:

- the page emits **no** `href`, `src` or form `action`, so there is nothing
  whose root-relative path would break;
- auto-refresh is a `<meta refresh>` with no URL, so it reloads whatever
  address the browser is on;
- Tailscale Serve strips the mount point before proxying and re-prefixes any
  `Location` header on the way back (`ipn/ipnlocal/serve.go`), so `brokerd`
  sees ordinary paths.

`TestServer_WorksBehindAPrefixStrippingProxy` reproduces that arrangement,
including a request to the mount point with no trailing slash, and
`TestPage_EmitsNoAbsoluteURLs` guards the invariant it depends on.

Nothing here is Tailscale-specific except the header name. Any proxy that
authenticates a user and sets that header, on a loopback-only listener, has
the same properties — and any deployment that would rather not trust a
header at all should leave this off and use one of the other three paths in
§2.1.

## 3. `$SYS` and mochi-mqtt's own HTTP stats — an explicit caveat

- mochi-mqtt ships an internal `$SYS` topic tree (MQTT) and can expose an
  HTTP stats listener (`listeners.NewHTTPHealthCheck`,
  `docs/architecture.md` §3). **Both are unauthenticated by default.**
- **`$SYS` MQTT topics** stay covered by the deny-all ACL rule
  (`docs/security.md` §3's example ACL ends in `{Filters: auth.Filters{"#":
  auth.Deny}}`, which also denies `$SYS/#` to any account without an
  explicit filter for it) — no board account needs to read `$SYS`, so no
  exception is carved out for it.
- **mochi-mqtt's HTTP stats listener**, if enabled at all, must be bound
  to `localhost` only (or not enabled) — it must never be reachable on the
  reverse proxy. `brokerd`'s own `/api/v1/*` endpoints (§1) are
  the intended public-facing surface; if mochi-mqtt's built-in stats are
  useful internally, read them over the loopback bind, not by exposing
  them.

## 4. Counter definitions

These are the concrete counters the endpoints in §1 surface, matching what
`docs/runbook.md` §5 step 7 and §9 expect to be able to check:

- **Decrypt-failure rate**: count of `raw_frames` rows per unit time with
  `decode_status = decrypt_failed`, broken down by `channel_segment`
  (ADR-4).
- **Duplicate deliveries**: the `duplicate` bucket in
  `decode_failures_by_reason` (ADR-14). Not an error — firmware
  re-delivers packets routinely (a single board was observed sending the
  same packet 3× in ~16 seconds), so a steady nonzero count is normal.
  It is worth watching as a **ratio** against `decoded`: a sudden jump
  suggests a board is retrying much harder than usual (weak WiFi,
  flapping MQTT connection).
- **Per-topic throughput**: message count per unit time, keyed by
  `channel_segment` (not the full topic, to avoid an unbounded cardinality
  key if the topic's `{node}` segment ever turns out to vary per packet).
- **Auth failures/bans**: from the in-memory counter store (ADR-5) —
  total failures, and currently-active bans with their expiry.
- **Last-seen per board**: updated whenever a `raw_frames` row is
  inserted for that `board_id`; "online" in `/api/v1/nodes` means
  last-seen within some small multiple of the boards' expected publish
  interval (exact threshold is an implementation detail, not specified
  here).
- **Disk usage**: the SQLite file's size on disk, checked via `os.Stat`,
  not a SQL query — surfaced so an operator notices retention
  (`docs/adr.md`'s ADR-7) needs tightening before the disk fills.
- **Storage queue drops**: ADR-3's drop-and-count counter, broken down by
  nothing further (a single running total is enough to notice the problem
  exists; per-topic breakdown isn't necessary for a policy that's meant to
  be rare).
- **Outbound relay**: `dry_run_total`/`published_total`/
  `publish_failures_total`, each broken down by rule ID (ADR-12,
  `docs/outbound-relay.md` §8). No message content or coordinates in the
  counters or their logs — counts only.

### 4.1. Report-only counters

These come from hooks that deliberately change nothing — they exist because
the event they describe is otherwise invisible ("an absent log
line is not an absent event"). Exposing them here is the whole point: a
counter no consumer can read is the same as no counter.

| Field | Type | Meaning |
| --- | --- | --- |
| `listener_noise_suppressed_total` | per category | WARN lines demoted to DEBUG, by category (`tls_handshake`, `malformed_packet`). Internet-wide scanning, not a deployment fault. Restore the lines with `-log-level debug` |
| `board_node_id_mismatches_total` | per observed value | Frames whose `gateway_id` disagrees with the board's configured `node_id` — a board was reflashed, or two boards share an MQTT account |
| `acl_denials_total` | per client | Publishes and subscribes the ACL refused. Counted per account; the *log* line is emitted once per (client, topic, direction) and that table is capped at 1000 entries, after which refusals are still counted but no longer logged individually (one warning says so). mochi-mqtt refuses a QoS 0 publish with no log and no error to the client, so this is the only record |
| `session_takeovers_total` | per board | Times a new MQTT session replaced a live one for that board. A Meshtastic node reboots on every config change -- **changing the owner name reboots it** -- so this rises whenever boards are reconfigured. It exists because the replaced session's disconnect is deliberately *not* reported: mochi-mqtt closes the old session after accepting the new one, and treating that as an outage marked a publishing board absent and paged whoever wired an alert to it |
| `downlink_missed_total` | per board | Frames published while that configured board was disconnected. Downlink is QoS 0 with a clean session, so nothing is replayed on reconnect (`docs/architecture.md` §8.1) |
| `connected_boards` | array of board ids | Boards with a live MQTT session right now — the only way to distinguish "no traffic" from "board absent" |
| `event_hooks` | object, per target name | `fired_total`, `failed_total`, `dropped_total`, `ratelimited_total`, `suppressed_total`, `dry_run_total`, `disabled_targets` (`docs/event-hooks.md` §7). An empty object means no hooks are configured, which is distinguishable from hooks that never fired |

All are in-memory and reset when `brokerd` restarts. None of them is an error
budget: a non-zero value is information, not a failure.

## 4.9. Node names

A node's **name and its id are shown separately**: the Name column carries the
long name with the short name after it (`Some Node (SOME)`, the same string a
hook payload sends as `from_name`), and the id keeps its own column. Gluing them
into one string hid the short name -- which is what the node's own screen shows
-- and made the id read as part of the name.

Every list that shows a node id shows a **Name** column beside it, and a
**Nodes** section lists what each node currently calls itself and when it was
last heard.

The page shows the current state only. `node_names` also records the first
sighting, how many NODEINFO frames taught the name and how many times it
changed, and a rename is logged when it happens -- but that is a question for
the database, not for a page whose job is "what is true now"
(`docs/storage-schema.md` §9).

A node that has never broadcast `NODEINFO_APP` has no name, and the page renders
a dash rather than repeating the id as a name -- the same rule as every other
unstated value (ADR-15).

A long name is arbitrary text chosen by whoever owns a radio in range, and it
reaches the page over the air. `html/template` escapes it; a test asserts a name
containing markup renders inert.

## 5. The HTML page

`GET /` renders a single page from the same data the JSON endpoints expose,
plus a few queries of its own. It is read-only, like everything else here.

| Section | Shows |
| --- | --- |
| Boards | Per board: whether traffic arrived recently, whether an MQTT session is live **right now**, the last frame's time, how long it has been quiet, total frames, and any `downlink_missed` or `node_id` mismatch |
| Traffic | Frames per portnum, and the last 25 frames with board, portnum, sender, SNR and hop count |
| Messages | The last 15 text messages. Frames marked `duplicate` are excluded: a re-delivery is not new content (ADR-14), and rows written before suppression existed would otherwise show one message three times |
| Health | Storage queue drops, decode failures by reason, suppressed listener noise, ACL refusals, `node_id` mismatches, auth failures and active bans |
| Outbound | Relay publishes per rule and every event-hook counter, including targets auto-disabled after repeated failures |
| Telemetry | Latest device metrics per source — empty so far, and the page says why in words rather than showing an empty table |

Every list is a **window, not the record**, and the page says so: it shows
"the most recent 25 of 215 stored frames" and offers `?frames=N` /
`?messages=N` to widen it, capped at 500 rows. An out-of-range or unparseable
value is clamped rather than rejected — answering 400 to a mistyped
monitoring URL would be the least useful possible response. The remaining
sections are bounded by configuration (boards, relay rules, hook targets) or
by fixed vocabularies (decode statuses, noise categories), and telemetry shows
at most one row per source.

Deliberate properties:

- **No JavaScript, no external requests.** The page must work over an SSH
  tunnel or a tailnet with no internet route. A monitoring page that needs a
  CDN is one more thing that can be down while you are finding out what is
  down. Auto-refresh is a `<meta http-equiv="refresh">`, every 60 s.
- **Two board facts, not one.** "Traffic" is derived from stored frames and
  answers *has anything arrived*; "MQTT session" is the live connection.
  A board can be connected and quiet, or disconnected with a recent frame.
  When session state is unavailable the page says `unknown` rather than
  `absent`.
- **An absent measurement renders as `—`, never as 0** (ADR-15). A frame the
  gateway generated itself states no SNR at all.
- **The page contains message text**, so it is `Cache-Control: no-store`, and
  publishing it publishes the messages. Message bodies are escaped with
  `html/template`: anyone within radio range can send one.
- The token never appears in the rendered page, which a test asserts.
