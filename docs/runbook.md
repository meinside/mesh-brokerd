# Runbook

Verification scenarios, connection procedures, and troubleshooting. Where a
procedure hasn't actually been run yet, only the steps are written down;
actual results (success/failure, logs) get added here once verified.

## Prerequisite: installing the Meshtastic CLI

Sections §3, §5, §6, and §7 below assume the `meshtastic` CLI (the Python
package's console script) is available on whichever computer is doing the
work. Install it once per computer that will ever need it (the office Mac,
and/or the home RPi5).

- **Check first**: `python3 -V` and `pip3 -V` should both return a version.
- **Serial driver**: for USB-serial work (§2, §6, §7) the computer needs the
  right USB-to-UART driver installed for whichever board is in use —
  CP210x or CH9102 for the currently deployed Heltec V4 boards
  (`docs/hardware.md` §2); a different board model may use a different
  chip/driver (`docs/hardware.md` §1). After plugging the board in, confirm it shows up as a device
  (`ls /dev/cu.usbmodem*` on macOS, `ls /dev/ttyUSB*` or `/dev/ttyACM*` on
  Linux) before troubleshooting anything CLI-related.

**macOS (office) / Raspberry Pi OS (home)** — both are PEP 668
("externally-managed-environment") systems, so installing via `pipx`
rather than bare `pip3` avoids fighting the system Python:

```bash
# macOS
brew install pipx
pipx ensurepath
pipx install "meshtastic[cli]"

# Raspberry Pi OS / other Debian-based Linux
sudo apt update && sudo apt install -y python3-pip pipx
pipx ensurepath
pipx install "meshtastic[cli]"
```

Open a new terminal (so the `PATH` update from `pipx ensurepath` takes
effect), then confirm:

```bash
meshtastic --version
```

## 1. Confirmed environment facts

- The Meshtastic web flasher confirmed a supported firmware image exists
  for the Heltec V4.
- No client isolation on the office WiFi — devices on the same network can
  reach each other with just the WiFi password.
- Meshtastic's `mqtt.address` is a single string and does not support
  redundancy (primary/secondary), confirmed against the protobuf
  definition.
- See `docs/environment.md` for further details.

## 2. Protocol capture spike (reusable)

Run once per new board model or firmware version, to confirm the wire format
`internal/decode` assumes still holds. Results from the first run are under
`testdata/`.

1. Run a throwaway broker on a laptop (no `sudo`: mochi-mqtt or `mosquitto`
   on a high port), point one board's `mqtt.address` at it, and capture the
   raw envelope bytes per topic.
2. Send one known plaintext on the private channel and one direct message.
3. Assert the captured bytes against the schema, **never against this
   project's own encoder** — a shared wrong assumption passes every
   round-trip test (`internal/decode/wireformat_test.go`).

## 3. Verifying `brokerd` hosting (after choosing a deployment path)

Exact commands differ depending on the path chosen in `docs/deployment.md`
(public server vs. home lab), so only the steps common to both are listed
here.

1. Deploy `brokerd` on the target server and register it with `systemd`
   (`Restart=always`).
2. Confirm the domain/TLS was issued correctly (e.g. check the certificate
   chain with `openssl s_client -connect <domain>:<port>`). `brokerd`
   manages this itself (ADR-8, `internal/tlscert`). To re-verify the
   DNS-01 flow end-to-end against the real domain and DNS provider
   (e.g. after rotating the provider's API token), run
   `internal/tlscert`'s manual end-to-end test
   (`go test -tags tls_e2e -count=1 ./internal/tlscert/... -run TestManualE2E -v`,
   with `CGO_ENABLED=1` and the real `.env` sourced) — it performs a
   real ACME exchange against Let's Encrypt's staging CA, excluded from
   `make check`/CI via the `tls_e2e` build tag (an external-network
   dependency, same isolation principle as
   `-tags hardware`).
3. **Confirm each board's own `mqtt.address` is actually set to
   `<brokerd public domain>:8883` — not still the stock
   `mqtt.meshtastic.org`.** The stock config already comes pre-filled
   with the public server + demo credentials (confirmed on a real test
   board, `docs/firmware-config.md` §11.A), not literally blank — this
   fails silently, not loudly, so check it explicitly rather than
   assuming initial provisioning took:
   ```bash
   meshtastic --host <board IP> --get mqtt.address
   ```
   Do this once right after provisioning, and again any time a board is
   factory-reset or re-provisioned.
4. Create accounts (use strong random passwords, and confirm they're
   stored as bcrypt hashes in `brokerd`'s account store).
5. Verify **from an external network** (i.e. not the office or home
   network — for example, mobile data). The test topic must fall inside
   the account's allowed ACL filter (`msh/pvt/2/e/#`, `docs/security.md`
   §3) — it is a synthetic connectivity-check topic, not a real channel,
   so a fixed suffix such as `.../pvt/_test` is used to keep it visibly
   distinct from actual channel traffic:
   ```bash
   mosquitto_pub -h <domain> -p <port> --tls-use-os-certs \
     -u <board-id> -P <PASSWORD> -t 'msh/pvt/2/e/pvt/_test' -m 'hello'
   ```
   (`mosquitto_pub`/`mosquitto_sub` CLI tools work fine here even though
   the broker is mochi-mqtt — MQTT itself is a standard protocol, so
   client tooling doesn't care which broker implementation is on the other
   end.)
6. Subscribe locally (on the server) and confirm delivery.
7. Attempt to connect with a wrong password and confirm the failure is
   logged, and that repeated attempts actually get that IP banned
   (verifying the custom hooks described in `docs/security.md` §3).
8. **Finding a board's own node ID** (only needed if the optional
   `outbound_relay` feature's `origin_scope: "own_boards_only"` is ever
   used, `docs/brokerd-config.md`'s `boards[].node_id`):
   ```bash
   meshtastic --host <board IP> --info
   ```
   Under `Nodes in mesh`, find that board's own entry and read its
   `user.id` field (e.g. `"!4a2d2b38"`) — copy it exactly as shown, `!`
   included; no manual hex/decimal conversion needed. The same value is
   also visible in the companion app's device info screen, or (once
   provisioned) via `meshtastic --port <serial>` if connected over USB.

## 4. Companion app connection procedure (WiFi/TCP, 4403) — identical at both sites

1. Confirm the client (phone/PC) is on the same WiFi band as the board.
2. Find the board's IP (the router's DHCP client list, or the board's OLED
   screen).
3. In the companion app, choose the "Network/TCP" connection method and
   enter `<IP>:4403`.
4. If the IP is unknown or the connection fails, try
   `meshtastic.local:4403`.
5. Confirm normal operation after connecting: browse the node list/
   channels/settings, and send a test message.

The CLI can verify the same thing (once installed):

```bash
meshtastic --host <IP> --info
meshtastic --host <IP> --nodes
meshtastic --host <IP> --sendtext "test"
```

## 5. Verifying `brokerd` (storage/auth/monitoring)

1. Confirm mochi-mqtt's listener opens correctly on `brokerd` startup (via
   logs).
2. Send a test message from the office board's companion app and confirm a
   `raw_frames` row is added to `brokerd`'s SQLite store.
3. Confirm decryption with the channel PSK succeeds and plaintext lands in
   `text_messages` (verify with a message actually sent from real
   hardware — known test vectors alone aren't sufficient).
4. Send from the home board too, and confirm both sites' messages get
   stored.
5. Force-kill and restart `brokerd`, and confirm it recovers automatically
   and previous data is retained (if registered as a `systemd` service).
6. Deliberately try to decrypt with a wrong channel key and confirm the
   failure is recorded in the event log, and that **the whole process
   doesn't crash thanks to `recover()`** (this verifies the defense against
   the blast-radius risk in §3 of `docs/architecture.md`).
7. Confirm the monitoring endpoints (`docs/monitoring-api.md`: `/health`,
   `/api/v1/*`) respond, and that mochi-mqtt's own `$SYS`/HTTP stats (if
   enabled at all) are reachable only on `localhost`, never on the public
   monitoring API (`docs/monitoring-api.md` §3).

## 5.5. Provisioning a board (parametrized)

The sequence below provisions any board, at any site. Substitute the
placeholders; nothing in it is specific to a particular board or site
(`docs/architecture.md` §10.1). It is the sequence actually used for the
second board, in the order that matters.

Set these first, so nothing below has to be edited inline:

```bash
P=$(ls /dev/cu.usbmodem* | head -1)   # or --host <ip> once the board is on WiFi
BOARD_ID=<board-id>                   # also the MQTT username and the 4-char short name
BROKER=<brokerd host>:8883
CHANNEL=<private channel name>
```

`BOARD_ID` doubles as the companion app's short name, which is capped at
**4 characters** (`--set-owner-short`, CLI reference), so pick an ID that
fits if you want the two to match.

Take a snapshot first — it is the only record of what the board looked like
before, and it settles "was this always set?" questions later:

```bash
meshtastic --port $P --info > "$BOARD_ID-before.txt"
```

**Step 1 — identity and radio.** No MQTT involvement, so nothing can leak
yet:

```bash
meshtastic --port $P --set-owner "$BOARD_ID" --set-owner-short "$BOARD_ID"
meshtastic --port $P --set lora.region KR
meshtastic --port $P --set lora.modem_preset LONG_FAST
meshtastic --port $P --set lora.ignore_mqtt false   # NOT optional; see below
meshtastic --port $P --set lora.ok_to_mqtt false
meshtastic --port $P --set position.gps_mode NOT_PRESENT
meshtastic --port $P --set position.position_broadcast_smart_enabled false
```

`position.gps_mode` must be `NOT_PRESENT` on a board with no GPS hardware.
Left at `ENABLED` the firmware keeps looking for a fix it will never get and
**broadcasts POSITION_APP packets with latitude/longitude of zero**, mixed in
among any real ones. Observed on a live board, and it is not obvious from the
outside: the packets decode fine and only the coordinates are wrong
(`docs/outbound-relay.md` §4.1).

`position_broadcast_smart_enabled` must be `false` for a fixed-position
board. Smart broadcasting only transmits after the node has *moved* (default
minimum 100 m), so a board that never moves broadcasts erratically or not at
all.

**Position source**: leave it unset unless this board's position is going to
be relayed (`docs/outbound-relay.md` §2). If it is, set a fixed position
instead of disabling it:

```bash
# Only for a board whose position is deliberately shared:
meshtastic --port $P --setlat <lat> --setlon <lon>   # also sets fixed_position
meshtastic --port $P --ch-set module_settings.position_precision 13 --ch-index 1
meshtastic --port $P --ch-set module_settings.position_precision 0 --ch-index 0
```

The precision goes on the **private** channel, not the primary one, and the
primary's location sharing is turned off — only the lowest-indexed secondary
channel with location sharing enabled broadcasts automatically, and a
firmware caveat lets the primary's precision override a secondary's
(`docs/outbound-relay.md` §2).

`lora.modem_preset` must match on every board on the mesh: **the channel
hash depends on it** (`docs/firmware-config.md` §4), so a mismatch makes
boards silently fail to decrypt each other's packets rather than reporting
an error.

`lora.ok_to_mqtt false` asks other gateways not to uplink this node's
packets. It is only honoured on channels using the default PSK — channels
with custom keys ignore it (official LoRa config docs) — so it does not
protect the private channel. Keep it `false` anyway: it governs the
*primary* channel, which does use the default PSK, and `false` is what
keeps that traffic off public maps.

`lora.ignore_mqtt` must be set explicitly even though it is documented as a
default. One of the two deployed boards shipped with it `true`, which makes
the board discard all MQTT downlink while looking completely healthy
(`docs/firmware-config.md` §13).

**Step 2 — MQTT target, while MQTT is still disabled.** This ordering is
the point of the whole procedure. Stock firmware ships `mqtt.address`
pre-filled with the **public** server and demo credentials, so enabling
MQTT (or an uplink-enabled channel) before overwriting it points the board
at `mqtt.meshtastic.org` (`docs/firmware-config.md` §11A):

```bash
meshtastic --port $P --set mqtt.address "$BROKER"
meshtastic --port $P --set mqtt.username "$BOARD_ID"
meshtastic --port $P --set mqtt.password "<that account's password>"
meshtastic --port $P --set mqtt.tls_enabled true
meshtastic --port $P --set mqtt.encryption_enabled true
meshtastic --port $P --set mqtt.root "msh/pvt"
meshtastic --port $P --set mqtt.json_enabled false
meshtastic --port $P --set mqtt.map_reporting_enabled false
meshtastic --port $P --set mqtt.proxy_to_client_enabled false
```

**If this board feeds the outbound relay's map-report path, that
`map_reporting_enabled false` line undoes it.** This block is the baseline for a
board that only bridges the private channels; a board meant to publish map
reports needs `mqtt.map_reporting_enabled true` **and**
`mqtt.map_report_settings.should_report_location true` (both, and the CLI sets
only the field named — `docs/firmware-config.md` §11 C/§14). Re-provisioning a
board from this list alone silently stops its map reports, and the next
missing-from-the-map report is an hour away at best
(`publish_interval_secs` ≥ 3600).

`mqtt.encryption_enabled` is set explicitly rather than assumed. Its
stock default is not verified here, and the official MQTT module docs are
blunt about the failure mode: "All messages are sent to the MQTT broker
unencrypted if this option is not enabled, **even when your uplink channels
have encryption keys set**." With it off, private-channel traffic reaches
`brokerd` in cleartext and nothing reports a problem — `brokerd` would
simply store readable payloads. `docs/security.md` §7 depends on this being
on.

Read it back before continuing:

```bash
meshtastic --port $P --get mqtt.address
meshtastic --port $P --get mqtt.username
```

**Step 3 — WiFi.** The board goes online, still with MQTT off:

```bash
meshtastic --port $P --set network.wifi_ssid "<ssid>"
meshtastic --port $P --set network.wifi_psk "<psk>"
meshtastic --port $P --set network.wifi_enabled true
```

**Step 4 — the private channel.** `--ch-add` is incompatible with
`--ch-index`, and afterwards `--ch-set` applies to the newly added channel,
so add it on its own and confirm the index before setting the rest:

```bash
meshtastic --port $P --ch-add "$CHANNEL"        # name is capped at 10 chars on this path
meshtastic --port $P --info | grep -i -A3 'Index 1'
meshtastic --port $P --ch-set psk "base64:<channel psk>" --ch-index 1
meshtastic --port $P --ch-set uplink_enabled true --ch-index 1
meshtastic --port $P --ch-set downlink_enabled true --ch-index 1
meshtastic --port $P --ch-set uplink_enabled false --ch-index 0
meshtastic --port $P --ch-set downlink_enabled false --ch-index 0
```

The primary channel is explicitly *not* relayed
(`docs/firmware-config.md` §7).

**Step 5 — enable MQTT, last:**

```bash
meshtastic --port $P --set mqtt.enabled true
```

**Step 6 — verify from the server**, not from the board:

- `auth: accepted username=<board-id>` appears in `brokerd`'s log.
- A message sent on the private channel from the companion app lands in
  `raw_frames` and decodes into `text_messages`.
- Downlink reaches this board: publish from the server with
  `internal/decode/downlink_hardware_test.go` (`-tags hardware`) and
  confirm the message appears in the app. **Do not skip this** — uplink
  working tells you nothing about downlink, which is exactly the trap in
  `docs/firmware-config.md` §13.

Secrets appear in shell history. Prefix the commands with a space (with
`HISTCONTROL=ignorespace`) or read the values from a file.

## 5.6. Provisioning a non-gateway node (its traffic should reach `brokerd`)

A node with no network of its own — a battery-powered or WiFi-less board —
reaches `brokerd` only by being **overheard by a gateway**, which then uplinks
it. Three things decide whether that happens and only one of them is obvious,
so this is a separate sequence rather than a footnote to section 5.5.

**What not to set**, because it wastes a session: nothing under `mqtt.*` (this
node has no network to reach a broker with) and no `uplink_enabled` /
`downlink_enabled` on this node (the flags that matter belong to the
*gateway*, for the channel the packet arrived on).

```bash
P=$(ls /dev/cu.usbmodem* | head -1)   # USB only: a WiFi-less node has no --host
NODE=<node-id>                        # for file names and the test string
```

**Step 1 — snapshot first.** It is the only record of the "before" state, and
`--info` omits every `false`/`0`, so an absent setting means "default", not
"unset":

```bash
meshtastic --port $P --info > before-$NODE.txt
```

**Step 2 — join the private channel with a byte-identical name and PSK.**
Channel matching is by hash of name + PSK, so a single character of difference
means the gateway cannot decrypt and therefore cannot uplink. Copying the URL
from a gateway removes the chance of a typo:

```bash
meshtastic --host <gateway ip> --qr-all      # on a gateway: prints the URL
meshtastic --port $P --seturl '<url>'        # on this node
```

`--seturl` **replaces** the channel set, which is what step 1 protects
against.

**Step 3 — allow gateways to uplink this node's packets.** This is the one
irreversible step in this procedure, and the decision point: the flag is global
consent for **any** gateway in range to uplink to **any** server, not consent
scoped to `brokerd`. Work through `docs/firmware-config.md` §16's "What
enabling it exposes" and its pre-flight checklist before running this — at
minimum, step 4 below, and knowing that the node's name and any primary-channel
telemetry become public:

```bash
meshtastic --port $P --set lora.config_ok_to_mqtt true
```

It is required for the uplink to work at all, and it is invisible in two ways:
the default `false` is omitted from `--info`, and a gateway that declines to
uplink logs nothing on the server side — the frame simply never arrives.

**Step 4 — GPS-equipped nodes only: stop sharing location on the primary
channel.** The primary channel's stock `position_precision` is `13`, not `0`,
and step 3 makes that publishable by any gateway in range, not just this
deployment's:

```bash
meshtastic --port $P --ch-set module_settings.position_precision 0 --ch-index 0
```

**Step 5 — verify from the server**, using a string unique to this attempt:

```bash
meshtastic --port $P --ch-index <private index> --sendtext "$NODE-uplink-check-1"
```

```sql
SELECT substr(r.received_at,1,19) AS arrived,
       printf('0x%08x', t.from_node) AS from_node,
       t.text
  FROM text_messages t
  JOIN raw_frames r ON r.id = t.raw_frame_id
 ORDER BY t.id DESC LIMIT 5;
```

The join is not decoration: `text_messages.received_at` is a copy of
`raw_frames.received_at`, and what the *packet* stated is `raw_frames.rx_time`.
For "did it get here", read arrival. For "when was it sent", read `rx_time` --
and expect a gap: one message sat in a gateway's queue for 14m37s across a
brokerd restart (`docs/storage-schema.md` §8.2).

Match that string, not a row count: a count that went up answers "did
anything arrive", which is a different question and has produced false
positives in this project more than once. Note `received_at` is RFC 3339
**text**, not a Unix epoch (`docs/storage-schema.md`) — compare it as a
string.

**Step 6 — if it does not arrive**, tail the *gateway* over USB, which is the
only place the refusal is visible:

```bash
meshtastic --port <gateway serial> --noproto
```

| What you see | What it means |
| --- | --- |
| `MQTT onSend - Not forwarding packet due to DontMqttMeBro flag` | step 3 did not take effect |
| `MQTT Publish msh/<root>/2/e/...` | the gateway did its part; the problem is server-side |
| neither, and no receive line at all | the packet never arrived over LoRa — channel or range, not MQTT |

## 6. When serial access is needed (an optional extension point)

> USB-C serial is not required for the core data flow
> (`docs/architecture.md` §5). But if a board at some site really is
> connected to a computer, and that computer happens to be running a
> serial-based tool, **that process holds the port exclusively** and no
> other serial client can use it at the same time.

1. Stop whatever process is currently holding the port.
2. Confirm the port is actually free (e.g. `lsof /dev/cu.usbmodem*`).
3. Do whatever's needed (config changes, entering a PSK, etc.) via the
   serial CLI (`meshtastic --port /dev/cu.usbmodem*`) or the app's USB
   connection.
4. End the session once done.
5. Restart whichever serial tool was running before (if any).

## 7. Recovering WiFi access after a password change (via USB serial)

> **Why this is its own procedure, not just "use BLE":** on the currently
> deployed ESP32-based boards, Meshtastic
> disables BLE whenever `network.wifi_enabled = true` **in config** —
> regardless of whether the WiFi connection itself is actually up. So once a
> board's WiFi password is rotated (e.g. the office WiFi's quarterly
> rotation), the board keeps retrying the old password, fails to
> associate, but BLE stays off anyway. **Both BLE and WiFi/TCP 4403
> become unreachable at the same time** — the companion app has no path
> in. USB-C serial is the only path that doesn't depend on either
> interface, which is why it's kept as an extension point at all
> (`docs/architecture.md` §5) rather than being purely optional in
> practice.

1. Physically connect the affected board to a computer via USB-C.
2. Follow the port-contention check in §6 (stop/confirm free before
   proceeding).
3. Update the WiFi credential over serial:
   ```bash
   meshtastic --port /dev/cu.usbmodem* --set network.wifi_psk "<new PSK>"
   ```
   (Use the app's USB connection mode instead if preferred — same effect.)
   Only `wifi_psk` needs changing unless the SSID itself changed too.
4. Reboot the board (`meshtastic --port /dev/cu.usbmodem* --reboot`, or
   power-cycle).
5. Confirm it reassociates and BLE turns back off as expected:
   ```bash
   meshtastic --host <IP> --info
   ```
   If step 5 fails, double-check the new password was typed correctly —
   there is no in-band way to verify a WiFi PSK short of a successful
   connection.
6. If USB serial itself isn't available at the moment (no computer
   currently on-site), the board is unreachable until one is. This is a
   direct consequence of choosing a WiFi network with a rotating
   password, which is the tradeoff to weigh when choosing which network a
   board joins.

## 8. Troubleshooting

| Symptom | Cause/explanation | Response |
|---|---|---|
| Messages from one site never appear at the other, but the database has them | Delivery failed, not recording: the receiving board was offline at that moment, and QoS 0 + `cleanSession` leave nothing to retain (`docs/architecture.md` §7) | Nothing recovers them. Check that board's reconnect rate and `keepalive_floor_seconds`; read `text_messages` for the record |
| The companion app shows nothing although the board received the messages | A node stores no history, and the first Phone-API client to connect drains its 32-entry queue — `meshtastic --host`/`--port` included | Connect the app first, run CLI afterwards; use `text_messages` for anything that must not be missed |
| A board's frames never appear in `raw_frames`, and the log shows nothing | Three causes look identical: (a) the sending node never set `lora.config_ok_to_mqtt` — logged on the *gateway's* serial only; (b) the gateway channel's `uplink_enabled` is off — logged nowhere; (c) `brokerd`'s ACL refused the publish, which mochi-mqtt does silently for QoS 0 | Check `acl_denials_total` first (rules out c), then attach to the gateway over USB (`--noproto`) and send one uniquely-worded message: `Not forwarding` = a, received-but-no-MQTT-line = b, `MQTT Publish` = the packet left the board |
| Hourly map reports arrive, so channel uplink "must be fine" | It does not follow: `perhapsReportToMap()` never consults the channel's `uplink_enabled` | Check the channel block in `--info`; an absent `uplinkEnabled` means off |
| `WARN listener=mqtt-tls error="..."` lines have stopped appearing | Expected: scanner TLS handshakes and non-MQTT bytes are demoted to `DEBUG` and counted in `listener_noise_suppressed_total` instead (`docs/monitoring-api.md`). Transport errors from real boards and auth failures are **not** suppressed | Read the counter; run with `-log-level debug` to see the individual lines again |
| `WARN board node_id does not match the gateway_id its frames carry` | The configured `boards[].node_id` has drifted from the board's real node number, so `outbound_relay` rules scoped `own_boards_only` silently stop matching | Compare the logged `observed_gateway_id` with config; if the board legitimately changed number, update `config.json` and restart. `brokerd` only warns — it never edits config |
| Board not visible over BLE | Expected (BLE auto-disables while WiFi is on) | Connect over WiFi/TCP (4403) instead |
| Board not visible over BLE **and** WiFi/TCP 4403 both fail | WiFi password was rotated; BLE stays off because `wifi_enabled` is still `true` in config even though the connection itself is failing | Use USB serial per §7 |
| `meshtastic.local` doesn't resolve | mDNS issue, or more than one board on the same segment | Connect directly by IP |
| TCP 4403 connection refused | Board's WiFi is down/rebooting, or a session limit was hit (unverified) | Reboot the board, re-check its IP |
| Serial tool reports "port busy" | Another process holds the port | Follow the contention procedure in §6 |
| A board can't reach `brokerd` | Domain/TLS problem, firewall, wrong password, or (on the home-lab path) a port-forwarding/Funnel issue | Re-verify from an external network, check the certificate/firewall/account |
| `brokerd` can't read messages | Channel PSK/nonce calculation error, wrong subscription topic | First confirm `raw_frames` is still growing (`decode_status` will show `decrypt_failed` or `unknown_channel`, `docs/storage-schema.md`), then re-check unit tests against the `testdata/` fixture |
| Board connects and its own messages arrive, but nothing sent from the other site ever reaches it | `lora.ignore_mqtt` is `true` on that board — it receives MQTT downlink and discards it. Looks healthy at every other layer (`docs/firmware-config.md` §13) | `meshtastic --host <ip> --get lora.ignore_mqtt`, then `--set lora.ignore_mqtt false`. Isolate first with §5.5 step 6's downlink test so you are not guessing |
| A board is connected but publishes nothing | Often nothing to publish: with no LoRa peers, a board's own periodic broadcasts go on the *primary* channel, which is deliberately not uplinked (`docs/firmware-config.md` §7) | Send a message on the private channel from the companion app before concluding anything is broken |
| Board authenticates, then every publish vanishes | Publishing outside the account's `acl_filters` — typically a wrong `mqtt.root`. mochi-mqtt logs ACL denials at **debug**, so this is invisible at the default level | Restart `brokerd` with `-log-level debug` and look for `failed allowed ACL check` |
| A board reconnects every few minutes, log shows `i/o timeout` | `mochi-mqtt`'s read deadline is the client's own keepalive x 1.5, and Meshtastic advertises 15 s -- so 22 s of silence, one missed PING, ends the session. Common on a network that delays or drops packets (`docs/environment.md`) | Check the `client keepalive` log line for the requested value and the resulting deadline, then set `listener.keepalive_floor_seconds` (60 gives a 90 s deadline). This treats the symptom; the network path is the cause |
| Startup logs `file permissions are looser than recommended` | A file holding message content or key material is readable beyond its owner (`docs/security.md`) | `chmod 600` the file, `chmod 700` the TLS cache directory. brokerd deliberately does not change it for you; if the mode is intentional the warning is the only cost |
| A non-gateway node's packets never appear in `raw_frames`, though the gateway hears it over LoRa on a shared channel | The sender leaves `lora.config_ok_to_mqtt` at the default `false`, so the gateway declines to uplink another node's packet to a broker at a public IP (`docs/firmware-config.md` §16) | On the **sending** node: `meshtastic --port <serial> --set lora.config_ok_to_mqtt true`. To watch the cause directly, tail the gateway over USB (`--noproto`) for `MQTT onSend - Not forwarding packet due to DontMqttMeBro flag`; `--info` cannot show the before state, since `false` is omitted |
| One private channel is delivered end to end while another is not | A per-channel fault; everything node-global would break both | §8.1 |
| `brokerd` process crashes entirely | A panic in storage/decoding wasn't caught by `recover()` (ADR-3, `docs/adr.md`) | Find the panic site from the logs and add a defense — this is exactly the blast-radius risk the design accepted, so treat it as high priority |

## 8.1. Per-channel faults

When one channel is delivered end to end and another is not, everything
node-global is already ruled out: `mqtt.address`, credentials, TLS, `mqtt.root`,
`lora.ignore_mqtt` and `lora.region`/`modem_preset` would break both channels or
neither. What differs is per channel, and these are the facts needed to tell the
cases apart.

- **`uplink_enabled` and `downlink_enabled` are independent**, so a board can
  receive a channel correctly and never publish on it, or the reverse.
- **A board subscribes one filter per channel** it holds with `downlink_enabled`
  (`docs/protocol-spec.md` §1.0.1), reported as `board_subscriptions`
  (`docs/monitoring-api.md` §4.1). A channel missing from one board's filter set
  is missing on that board, or has downlink off — nothing else reports this.
- **A subscription proves the *name*, never the PSK.** A channel is identified on
  the wire by a hash of name + PSK, which no topic carries: a board subscribed
  under the right name with the wrong key receives every frame and matches none.
  What settles it is that board publishing on the channel — `decoded` means the
  keys agree, `decrypt_failed` means they do not.
- **`--ch-index N` indexes that board's channel list**, whose order is not the
  same on every board, while an app sends on the channel picked by name. The
  channel a message actually used is in its topic, so `brokerd` can name it:

  ```bash
  sqlite3 "file:$DB?mode=ro" \
    "SELECT r.received_at, r.board_id, r.decode_status,
            COALESCE(t.channel_name, r.channel_segment) AS channel,
            COALESCE(t.text,'')
       FROM raw_frames r LEFT JOIN text_messages t ON t.raw_frame_id = r.id
      ORDER BY r.id DESC LIMIT 10;"
  ```

- **A direct message is not a channel test.** DMs are PKC-encrypted per node pair
  (firmware ≥2.5) and reach their addressee whatever the channel's state; an app
  test done by tapping a node is one. `brokerd` stores them as `pki_encrypted`.
- A private channel that ended up at **index 0** on a board can never uplink or
  downlink there: the primary channel is deliberately never relayed
  (`docs/firmware-config.md` §7).
- Frames published while a board held no connection are lost to it and counted in
  `downlink_missed_total`; QoS 0 with `cleanSession` leaves nothing to replay.
  A low-rate channel can be missed entirely this way.

## 9. Routine operations (once running)

- Check the backup schedule for `brokerd`'s SQLite archive (ADR-7,
  `docs/adr.md` — no automatic pre-deletion backup exists, so this is the
  operator's own schedule).
- Run `VACUUM` on a separate, infrequent schedule (`docs/storage-schema.md`
  §6) — not on every retention deletion pass.
- Regularly check `systemctl status mesh-brokerd`.
- Periodically review auth-failure logs/ban statistics
  (`docs/security.md` §3, `docs/monitoring-api.md` §1's
  `/api/v1/stats/auth`).
- Re-confirm the boards' TCP 4403 stays reachable only on the local WiFi
  band.
- **If the board's WiFi network rotates its password on a schedule (e.g.
  every 3 months on a corporate network), track that schedule and
  perform §7 proactively** rather than discovering the lockout reactively
  when the board silently drops off `brokerd`.

## 9.5. Backfilling stored frames after a decoder or schema change

When a column or a decoder is added, existing rows keep whatever the old
build wrote. `raw_frames.payload` still holds the bytes, so they can be
filled in (`docs/storage-schema.md` §7).

```sh
# 0. brokerd reads its environment, not .env -- source it for a hand run.
set -a; . ./.env; set +a

# 1. See what would change. Writes nothing.
mesh-brokerd -config <path>/config.json -reprocess dry-run

# 2. Apply. The tool copies the database with VACUUM INTO first and prints
#    where, so there is a version from before the rewrite.
mesh-brokerd -config <path>/config.json -reprocess apply

# 3. Check the result.
sqlite3 <path>/brokerd.db \
  "SELECT COALESCE(portnum_name,'(not decoded)') kind, COUNT(*) FROM raw_frames GROUP BY 1;"
sqlite3 <path>/brokerd.db "PRAGMA integrity_check;"
```

- **Safe with the service running.** Both sides use a 5 s busy timeout and
  this deployment writes a few frames an hour. It was run this way once, on
  207 rows, with no `SQLITE_BUSY` and no restart.
- **Read the `status_changes` map in the output.** Every transition is a
  change to a recorded fact — see §7's table for what each kind means.
- The pre-reprocess copies accumulate in the data directory. Delete the old
  ones once a run has been verified; they are full database copies.

## 9.7. Rotating a channel PSK

A frame is encrypted with the key its sender held, so a rotation is only
complete when **every** node has it. Rotating the boards one at a time leaves
the rest transmitting on a key `brokerd` no longer has, and those frames are
stored as `decrypt_failed` and stay that way -- the ciphertext is kept, but
nothing can open it afterwards.

That happened here: two nodes were rotated and one was not, and 20 hourly
position frames from it over the next 20 hours are permanently unreadable
(decided not to be worth a second key path).

1. Change the PSK on **all** nodes, including non-gateway ones, before updating
   `config.json`.
2. Update the channel's `psk_env` value in the data directory's `.env`, then
   restart `brokerd`.
3. Confirm the next frame from **each** node decodes:

   ```bash
   sqlite3 "$DB" "SELECT printf('!%08x',from_node), decode_status, count(*)
                    FROM raw_frames WHERE received_at > '<rotation time, UTC>'
                   GROUP BY from_node, decode_status;"
   ```

   Any node still showing `decrypt_failed` has not been rotated. Do not wait
   for a report to tell you: a board with the wrong key uplinks normally and
   logs nothing.

Renaming a channel is independent of the key -- the name is part of the topic,
the PSK is not -- so a rename alone changes nothing about decodability.

## 9.5.1. Finding out what an undecodable frame was

A frame stored as `decrypt_failed` has no `portnum`, because the portnum is
inside the encrypted `Data` submessage. Any query like "did we ever receive a
NODEINFO" is therefore blind to those frames, and reading its empty result as
"never sent" is wrong.

`internal/decode/undecodable_diag_test.go` (build tag `diag`, excluded from
`make check`) tries every PSK it is given against every stored failure and
reports the portnum it finds. Keys come from the environment; names are reported
as lengths only.

**Set `DB` first.** `sqlite3 "" ".backup /tmp/diag.db"` opens a transient
in-memory database, backs *that* up and exits 0, leaving a file with no tables:

```bash
DB=$(jq -r .storage.path config.json)   # or read storage.path by hand
test -s "$DB" || echo "DB is not a file: $DB"
```

```bash
sqlite3 "$DB" ".backup /tmp/diag.db"        # never read the live WAL directly
CGO_ENABLED=1 DIAG_DB=/tmp/diag.db DIAG_PSKS="<base64>,<base64>" \
  go test -tags diag ./internal/decode/ -run TestDiagUndecodableFrames -v
```

Give it the current key **and** any older one still in `.env`: a rotation is the
usual reason a frame stopped being readable. When no key works, the frames were
sent under a key this deployment never had -- which is itself the answer.

## 9.5.2. Finding out whether a board ever uplinked in the clear

`plaintext_uplinks_total` (`docs/monitoring-api.md` §4.1) is in-memory, so it
speaks only for the frames the running process has seen. The history is
answerable from `raw_frames.payload`: "arrived in the clear" is a property of
those bytes (`MeshPacket`'s `payload_variant` is `decoded` rather than
`encrypted`), and no channel key is needed to read it. SQL alone cannot — such a
frame is identical in every stored column to one `brokerd` decrypted itself.

```bash
sqlite3 "$DB" ".backup /tmp/diag.db"        # never read the live WAL directly
CGO_ENABLED=1 DIAG_DB=/tmp/diag.db \
  go test -tags diag ./internal/decode/ -run TestDiagPlaintextUplinks -v
```

It reports encrypted/plaintext counts per board and channel and the time range of
any plaintext run, and asserts nothing. Map reports are skipped (unencrypted by
design, `docs/firmware-config.md` §14). What to change on the board is §11 A's
`mqtt.encryption_enabled` row; a rotation afterwards does not un-publish what
already went out in the clear.

## 9.6. Opening the monitoring page

The page is `GET /` on the monitoring listener, which binds loopback
(`docs/monitoring-api.md` §5). Pick whichever route suits the deployment;
they are independent.

**a. SSH tunnel — nothing exposed, works everywhere**

```sh
ssh -L 9101:127.0.0.1:9101 <host>
# then open http://127.0.0.1:9101/ and paste the monitoring token into the
# browser's password prompt (any username)
```

**b. A private overlay network, e.g. Tailscale Serve**

```sh
tailscale serve --bg 9101      # publishes https://<host>.<tailnet>.ts.net/
tailscale serve status
```

To mount it under a path instead of at the root — useful if the node serves
anything else — add `--set-path`, and pass the same flags plus `off` to
remove it:

```sh
tailscale serve --bg --set-path=/brokerd 9101   # https://<host>.<tailnet>.ts.net/brokerd/
tailscale serve --set-path=/brokerd off
```

Serve strips the prefix before forwarding, and the page emits no absolute
URLs, so `brokerd` needs no configuration either way
(`docs/monitoring-api.md` §2.3).

Serve proxies tailnet traffic to `127.0.0.1:9101` and terminates TLS, so
`brokerd` needs no configuration change — its loopback default is exactly
what this wants. Two optional keys remove the password prompt by trusting
Serve's identity header (`docs/monitoring-api.md` §2.2):

```json
"monitoring": {
  "trust_tailscale_identity": true,
  "tailscale_allowed_logins": ["<your login>"]
}
```

Cautions, all of them checkable:

- **The serve configuration survives a reboot** when created with `--bg`: it
  is written to `tailscaled`'s state store under a `_serve/<profile>` key and
  read back on startup (`ipn/ipnlocal/serve.go`). Without `--bg` it lives only
  as long as the foreground command. Verify with `tailscale serve status`
  after `systemctl restart tailscaled`.
- **Never `tailscale funnel` this port.** Funnel is public and strips the
  identity header, so the page would refuse everyone — but the port itself
  would be exposed. `serve` and `funnel` cannot both hold a port; whichever
  ran last wins.
- Requests from **tagged devices** carry no identity and are refused. Use a
  user-owned device, or the token.
- Keep `monitoring.listen_addr` on loopback. `brokerd` refuses to start with
  identity trust on and a non-loopback listener.

**Diagnosing a 401.** Every refusal is logged with a reason, so this is a
lookup rather than a guess:

```sh
journalctl -u mesh-brokerd -n 20 | grep 'request refused'
```

| Logged reason | What it means |
| --- | --- |
| `no_credential` | Nothing was presented, and identity trust is off |
| `bad_token` | The token does not match |
| `no_identity_header` | Identity trust is on but Tailscale attributed nothing: a **tagged** device, or a client routed through an **exit node**, or a request that never went through the proxy |
| `identity_not_on_allowlist` | The login is logged next to it — compare with `tailscale_allowed_logins` |
| `identity_header_present_but_trust_disabled` | The header arrived but the config does not trust it |
| `funnel_request` | The port is exposed with `funnel`, not `serve` |

The line also carries `forwarded_for`, which names the tailnet address that
actually connected — the difference between a phone and the exit node it was
routed through.

**c. A reverse proxy** — see `deploy/nginx/monitoring-site.conf.sample`,
which documents forwarding the browser's own credential versus injecting the
token and authenticating users at the proxy.

Verify whichever route you chose:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9101/            # 401
curl -sS -o /dev/null -w '%{http_code}\n' -u :"$TOKEN" http://127.0.0.1:9101/  # 200
```

## 10. Moving the data directory

All of `brokerd`'s persistent state lives in one directory: the SQLite
database (plus its `-wal`/`-shm` files) and the ACME cache
(`listener.tls_cache_dir`). Keeping them under a single parent is
deliberate — the systemd unit grants write access to exactly that one
path (`ReadWritePaths=`), and splitting them would mean widening it.

Moving it is not just a `mv`. In order:

1. **Stop `brokerd` first.** The database runs in WAL mode
   (`docs/storage-schema.md` §4), so a live copy can lose whatever is
   still in the write-ahead log, or capture a torn state. A graceful stop
   (`SIGTERM`, which systemd sends) checkpoints the WAL — after a clean
   shutdown the `-wal`/`-shm` files should be gone. Verify before
   moving:
   ```bash
   sqlite3 <old>/brokerd.db "PRAGMA integrity_check;"
   ```
2. **Move the directory**, then check you did not accidentally nest it:
   `mv src dst` puts `src` *inside* `dst` when `dst` already exists, so
   confirm the files are where you expect rather than one level deeper.
3. **Re-check permissions.** A move can pick up the new parent's mode.
   The data directory and the ACME cache should stay owner-only:
   ```bash
   chmod 700 <new> <new>/tls-cache
   chmod 600 <new>/config.json
   ```
   The ACME account key and certificate key must remain `600`.
4. **Update all three references** — missing any one of them fails at a
   different time, which is what makes this error-prone:
   - `listener.tls_cache_dir` in `config.json`
   - `storage.path` in `config.json`
   - `ReadWritePaths=` **and** `ExecStart`'s `-config` in the systemd
     unit (`deploy/mesh-brokerd.service`), then re-copy it to
     `/etc/systemd/system/` and `systemctl daemon-reload`. A stale
     `ReadWritePaths=` does not stop startup: `brokerd` starts and then
     fails on the first write, because `ProtectSystem=strict` makes
     everything outside that path read-only.
5. **Verify the ACME cache was actually found** at the new location.
   Grep the startup log for a certificate request:
   ```bash
   grep -c "Obtaining bundled SAN certificate" <new>/brokerd.log
   ```
   This must be **0**. A non-zero count means the cache was not read and
   a fresh certificate was issued, which spends Let's Encrypt rate limit
   for nothing (ADR-8).
6. Confirm the row counts match what step 1 reported, and that an
   external TLS handshake still succeeds
   (`openssl s_client -connect <domain>:8883`).
