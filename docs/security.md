# Security

## 1. Decision records (ADRs)

> ADR-1 and ADR-2 below are specific to the public-exposure decision and
> stay in this document. Later, implementation-level ADRs (storage/relay
> isolation, decrypt-failure handling, auth-hook parameters, channel-key
> reload, retention, TLS ownership) are indexed in `docs/adr.md`.

### ADR-1: expose `brokerd` publicly

- **Decision**: deploy `brokerd` (MQTT broker + storage + monitoring) on a
  publicly reachable Linux server and expose it to the public internet over
  TLS.
- **Relationship to the earlier principle**: this repository's initial
  security principle was "no router port forwarding, never expose the
  broker to the internet." This decision **deliberately reverses that
  principle**.
- **Why**: the office board can never join a private network like
  Tailscale in the first place, so any design has to have some point where
  a board crosses the trust boundary onto the public internet. This design
  accepts that and focuses on making that one exposed point
  (`brokerd`) strongly authenticated and encrypted instead.
- **Risks accepted and mitigations**: see §2–§5.

### ADR-2: embed the MQTT broker via mochi-mqtt, and decouple hosting from any one method (Tailscale/home lab)

- **Decision**: embed mochi-mqtt (a Go library) into `brokerd` instead of
  running mosquitto as a separate process. Host it on a generic public
  Linux server, and drop Tailscale as a required element
  (`docs/deployment.md`).
- **Risk accepted**: mochi-mqtt has a shorter track record and a smaller
  maintainer pool than mosquitto (`docs/architecture.md` §3). Also, because
  the broker and storage logic share one process, a bug in storage can
  bring down the broker too (larger blast radius).
- **Mitigation**: storage/decoding code is defended with `recover()` and
  covered by unit tests. mochi-mqtt's own reliability is backed by passing
  the official Paho Interoperability Tests, an extensive unit test suite,
  and an active release cadence.

## 2. Limits of TLS (a fact that must be understood)

Checking the official Meshtastic firmware source (PR #2410) shows that
`mqtt.tls_enabled` on ESP32 devices — which covers the currently deployed
Heltec V4 boards, and, per the PR's own framing, ESP32-family targets
generally — behaves as follows:

> "This update... leveraging the `WiFiClientSecure` class with the
> `insecure()` setting. It does not provide server certificate validation
> as this would require uploading CA's, signatures, or CA bundles."
> — github.com/meshtastic/firmware/pull/2410

- TLS provides **encryption in transit** (protecting credentials/content
  from passive sniffing), but **the board does not validate the broker's
  certificate.** It offers no protection against an active MITM presenting
  a fake certificate.
- **Client certificates (mTLS) are also not supported by the firmware.**
- If a non-ESP32 board is ever used (`docs/hardware.md` §1),
  re-check that board's own `mqtt.tls_enabled` implementation before
  assuming this same certificate-validation gap applies — it is a
  firmware/platform detail, not a Meshtastic protocol guarantee.
- **This is accepted as a residual risk**: an active MITM cannot be solved
  given this structural firmware limitation. The account/ACL/monitoring
  layers in §3–§4 form the real line of defense instead.

## 3. Strong authentication — the layers actually applied in `brokerd` (mochi-mqtt)

mochi-mqtt's `hooks/auth` Auth Ledger provides per-account ACL rules out of
the box, but it **compares passwords in plaintext**
(`u.Password == RString(pk.Connect.Password)`, confirmed from source) and
has **no built-in automatic banning after repeated auth failures**. The two
items below are therefore implemented as custom hooks.

| Layer | Method | How it's provided | What it stops |
|---|---|---|---|
| Transport encryption | `mqtt.tls_enabled=true` + server-side TLS (Let's Encrypt, etc.) | `internal/tlscert` (go-acme/lego, DNS-01, ADR-8) | Passive sniffing |
| Account authentication | A unique account per board + a random password 32+ chars long | Built on the mochi-mqtt Ledger, **but passwords are stored as bcrypt hashes and compared via a custom `OnConnectAuthenticate` hook** | Brute-force, credential guessing/sharing |
| Least-privilege ACL | Today, every board account shares one filter (`msh/pvt/2/e/#`, the whole private-mesh prefix, deny-all fallback below it) — this is a shared-mesh scope, **not** a per-site scope; see the caveat below | Provided out of the box by mochi-mqtt Ledger ACL rules | Limits blast radius to "inside the private mesh" vs. "everything else"; does **not** stop one board account from reading/writing another board's topics under the current filter |
| Connection-attempt monitoring/banning | Automatically block an IP after repeated auth failures | **Implemented as a custom hook** (a per-IP failure counter, deny once a threshold is exceeded). mochi-mqtt logs failures in a structured form (`"client failed authentication check", "remote", ...`) but does not ban automatically | Automated scanning/brute-force |
| Periodic rotation | Rotate account passwords periodically (e.g. quarterly) | Operational procedure | Reduces the risk from long-lived leaked credentials |
| (Not applicable) mTLS | Not supported by the firmware | — | Documented as a residual risk only |

- Accounts: `alpha` and `bravo` today (the general,
  per-board account/ACL pattern this instantiates is described in
  `docs/architecture.md` §10.1 — a third board is just a third account).
  Passwords are stored as
  **bcrypt hashes** in `brokerd`'s account store (implementation is
  expected to use `golang.org/x/crypto/bcrypt`).
- **Caveat (not per-board scoping)**: the example ACL below gives both
  accounts the identical filter `msh/pvt/2/e/#`, i.e. today's model is one
  shared-mesh filter for every board, not a per-board-scoped filter. This
  is intentional while every board is owned by the same operator
  (`docs/architecture.md` §10.1). Per-board write scoping (e.g. restricting
  each account to publishing only its own `{node}` segment) is deferred
  until there is a reason to tighten it, since it depends on the `{node}`
  segment format (`docs/protocol-spec.md` §1).
- Example ACL (the `Ledger` struct `internal/auth` builds from config):
  ```go
  ACL: auth.ACLRules{
      {Username: "alpha", Filters: auth.Filters{"msh/pvt/2/e/#": auth.ReadWrite}},
      {Username: "bravo",   Filters: auth.Filters{"msh/pvt/2/e/#": auth.ReadWrite}},
      {Filters: auth.Filters{"#": auth.Deny}}, // deny everything else
  }
  ```

## 4. Trust boundaries

- **Inbound**: `brokerd` binds exactly one public port (8883, MQTT over TLS).
  The monitoring API and its HTML page bind loopback only and are reached over
  an SSH tunnel, a restricted reverse proxy, or a private overlay network
  (`docs/monitoring-api.md` §2.1). The page holds message plaintext, so
  whoever can reach it can read the mesh's traffic; publishing it publishes
  that.
- **An identity header is trusted only when the operator says so, and only on
  a loopback listener.** `monitoring.trust_tailscale_identity` is off by
  default and startup fails if it is on while the listener is reachable from
  elsewhere — otherwise anyone who could reach the port directly would simply
  set the header. A missing header is always a refusal, so exposing the port
  publicly (e.g. Tailscale Funnel, which strips identity) locks the page
  instead of opening it. Anything that can change configuration is
  file-level access on the server, never a network endpoint.
- **Message content**: channel PSKs stay on the boards and in `brokerd`'s
  config. The broker operator can read decrypted text (that is the point of
  storing it); nobody upstream can, because uplinks are channel-encrypted.
  Direct messages are PKI-encrypted end to end and remain opaque
  (`docs/protocol-spec.md` §3).
- **Outbound**: the selective relay is the one path by which anything leaves
  this deployment **under `brokerd`'s control**, and it is whitelist-only and
  off by default (`docs/outbound-relay.md`).
- **A member node's own `lora.config_ok_to_mqtt` is a second egress path, and
  not one this deployment can gate.** Setting it on a node consents to *any*
  gateway in range uplinking that node's packets to *any* server — typically a
  stranger's, whose stock address is the official public one. Private-channel
  payloads stay encrypted, but the envelope's metadata and everything on the
  default-key primary channel (name, position, telemetry) do not. It is a
  polite request honoured by official firmware, not a control, and nothing on
  the gateway or in `brokerd` can grant or revoke it. Read
  `docs/firmware-config.md` §16 — "What enabling it exposes" and its pre-flight
  checklist — before enabling it on any node, and expect what has already been
  published to stay published.
- **ACL refusals are logged and counted.** mochi-mqtt refuses a QoS 0 publish
  with a bare `return nil` — no log, no counter — which makes a misconfigured
  board indistinguishable from an idle one. A hook registered *after* the ACL
  ledger observes only refusals, logs one line per client/topic/direction and
  exposes `acl_denials_total`. It always returns `false`: mochi-mqtt's
  `OnACLCheck` is a first-true-wins OR, so returning `true` would grant what
  the ledger refused.
- **A `command` event hook is an execution path, and the one place this
  project refuses instead of reporting.** A hook command must be an absolute
  path, a regular file, executable and not writable by group or other, or the
  config fails to load: whoever can write that file decides what `brokerd`
  executes. The child is given `PATH` and `BROKERD_HOOK=1` only — never
  `brokerd`'s environment, which holds channel PSKs, the monitoring token and
  the DNS provider's API token. The payload arrives on stdin, so a message
  body never becomes part of a command line, and nothing is passed through a
  shell (`docs/event-hooks.md` §5).
- **A webhook target sees whatever its rules allow, in plaintext, at a third
  party.** `match.include_text` is therefore opt-in per target, a non-loopback
  URL must be `https`, and a signing secret is mandatory so the receiver can
  reject anything `brokerd` did not send.
- **File permissions are checked at startup and reported, never changed** — a
  mode may have been widened deliberately, and silently overriding an operator
  every restart is worse than saying it once.
- **If a board uses the serial↔MQTT proxy** (ADR-10), the proxy machine
  terminates the TLS session and holds that board's MQTT password, so it is a
  trusted party for transport — though channel content stays encrypted to it.


## 5. Warning on admin operations

- **Do not change admin channel PSK, channel keys, node-owner information,
  or other settings over untrusted WiFi** (public/guest/shared APs, etc.).
- Why: there's no trust at the link layer, and TCP 4403 is unauthenticated,
  so on such networks configuration values could be sniffed or tampered
  with.
- Recommended: if the board at that site happens to be connected to a
  computer via USB-C, perform key/PSK changes over that **serial**
  connection instead (`docs/architecture.md` §5, and the serial section of
  `docs/runbook.md`). If no computer is available for a serial connection,
  only use the companion app over trusted WiFi temporarily.
- If admin work over WiFi is unavoidable: use a dedicated SSID/isolated
  VLAN, rotate the key immediately afterward, and keep the work window as
  short as possible.

## 6. Channel/message encryption

- **`mqtt.encryption_enabled` is `false` out of the box, and its name says
  the opposite of what it does.** It is not "also encrypt": at `false` the
  board publishes every uplinked packet **decrypted**, which upstream's own
  documentation states happens "even when your uplink channels have
  encryption keys set". A correct 32-byte PSK on both boards protects nothing
  on the MQTT hop while this is off, and with the stock `mqtt.address` that
  plaintext goes to the public server. Keeping it `true` is what makes the
  point below true at all. It is a **gateway-side** setting — the publishing
  node's, not the sender's — so the exposure surface is the set of boards with
  `mqtt.enabled`, currently two, both confirmed `true`.
- Keeping `mqtt.encryption_enabled = true` means message bodies stay
  encrypted with the channel PSK even while passing through the broker —
  `brokerd`'s operator (i.e. us) cannot see plaintext at the broker level
  either; decryption is only possible where the storage logic itself holds
  the channel key.
- **The misconfiguration fails in the healthy-looking direction, so it is
  detected rather than assumed.** A decrypted frame parses, stores and reads
  exactly like an encrypted one, leaving every other counter normal.
  `internal/broker.PlaintextChecker` therefore warns once per (board,
  channel) and counts every occurrence as `plaintext_uplinks_total`
  (`docs/monitoring-api.md` §4.1). It warns and never refuses the frame:
  dropping it would destroy the only evidence, and the packet cannot be
  re-encrypted after the fact.
- `mqtt.json_enabled = false` and `mqtt.map_reporting_enabled = false`
  prevent plaintext leakage and location exposure.
- **The one deliberate exception**: the selective outbound relay
  (`docs/outbound-relay.md`, ADR-12) forwards specific, individually
  whitelisted, already-coarse data to the official public server — by
  design, not by accident, and disabled by default (§4 above). It never
  forwards raw channel content; only decoded fields from portnums that
  have an explicit rule.

## 7. Secrets management

- Never write WiFi passwords, channel PSKs, or MQTT account passwords as
  real values in **any** document. Only `<PLACEHOLDER>` forms are allowed.
- Real values live in `.env` (only `.env.sample` is committed to the
  repository) or `config.json` (only `config.json.sample` is committed).
- This repository is planned to be a **private GitHub repository**. Even
  so, the same "never commit real secrets" principle applies (in case of
  future collaborators, a switch to a public repo, or a leak incident).

