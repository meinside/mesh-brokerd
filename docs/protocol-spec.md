# Protocol Specification

This is what `brokerd`'s MQTT subscribe/decode logic is written
against. Verified against a real Heltec V4 (firmware `2.7.26.54e0d8d`);
test vectors live under `testdata/` (§5).

> **License note (ADR-13, `docs/adr.md`)**: everything below is described
> independently, in prose — never by importing `meshtastic/protobufs`'
> (GPL-3.0) `.proto` files or generated code. `internal/decode` must be
> implemented the same way: hand-written Go structs/parsing based on this
> document, not `protoc`-generated from their schema.

## 1. Topic grammar

```
{mqtt.root}/2/e/{channel}/{node}
```

With this project's `mqtt.root = msh/pvt` (`docs/firmware-config.md` §7),
that's `msh/pvt/2/e/{channel}/{node}`:

- **`{channel}`**: the plain configured channel name (e.g. `pvt`) —
  matches `ServiceEnvelope.channel_id` exactly. Not the base36-encoded
  `name.id`. Treated as an opaque string throughout (channel-key lookup,
  storage's `channel_segment` column) — never parsed or split further.
- **`{node}`**: the gateway's `!hex`-formatted node ID, matching
  `ServiceEnvelope.gateway_id` exactly — not the sender's decimal node
  number. Not required for decode correctness (the payload carries its
  own `gateway_id`/`from` fields redundantly).

### 1.0.1. What a board subscribes to

A board subscribes **one filter per channel** it holds with
`downlink_enabled`, of the form `{mqtt.root}/2/e/{channel}/+` — not a single
wildcard covering every channel. Observed on two live boards through
`board_subscriptions` (`docs/monitoring-api.md` §4.1), which reported exactly
three filters each, one per configured channel plus `PKI`.

Two things follow, and both matter when a channel is delivered to one site and
not another (`docs/runbook.md` §8.1):

- **A missing or downlink-disabled channel is visible from the server**: its
  filter is simply absent from that board's set, and nothing else reports it —
  no refusal, no log.
- **The reverse is not true.** A filter's presence proves the board holds a
  channel of that *name* with downlink enabled. It says nothing about the
  **PSK**, which never appears in a topic: a board subscribed under the right
  name with the wrong key receives every frame and silently matches none of
  them, since the channel is identified on the wire by a hash of name + PSK.
- `PKI` appears alongside the configured channels. Direct messages are
  PKC-encrypted per node pair (§3), and this project holds no key for them.

### 1.1. The second grammar: map reports

```
{mqtt.root}/2/map/
```

Note the **trailing slash** — the final topic segment is empty. There is no
`{channel}` and no `{node}` segment: the firmware builds this topic as
`root + "/2/map/"` and puts the *primary* channel's name in
`ServiceEnvelope.channel_id` instead, whatever channel the node actually
uses (`docs/firmware-config.md` §14). Confirmed both from firmware source
and from a live board's own publishes.

Consequences a decoder has to handle:

- **No channel segment means no channel-key lookup.** A map report is
  published as the MeshPacket's `decoded` (plaintext) variant, never
  encrypted, so there is nothing to decrypt and no key to find.
- **`storage`'s `channel_segment` is NOT NULL**, so `internal/decode` fills
  it from the envelope's `channel_id` — the only channel identity the packet
  actually states.
- **The packet carries no `id`.** The firmware allocates it zeroed and never
  sets one for map reports, so `id = 0` is normal here and not a sign of a
  malformed packet.

Rejecting this grammar is not a safe default. `internal/broker`'s worker
drops a message whose topic does not parse **before writing any
`raw_frames` row**, on the assumption that per-board ACLs make such a topic
unreachable. Widening a board's `acl_filters` to admit the map topic breaks
that assumption, and the result is traffic that arrives, is accepted by the
ACL, and then vanishes with only an `ERROR` log line to show for it —
indistinguishable, from the database, from a board that never published
(`docs/runbook.md` §8).

## 2. Envelope layering

```
MQTT payload bytes
  -> ServiceEnvelope (protobuf)
       1 .packet: MeshPacket
       2 .channel_id: string   (the channel name)
       3 .gateway_id: string   ("!hex" node ID of the node that published this)
  -> MeshPacket
       1 .from: fixed32        (sender node number)
       2 .to: fixed32          (destination node number; 0xffffffff = broadcast)
       3 .channel: uint32      (varint; channel *hash*, not the name — see below)
       4 .decoded: Data        (plaintext variant, for public/PKC-decoded packets)
       5 .encrypted: bytes     (ciphertext variant, the normal case for a PSK channel)
       6 .id: fixed32          (packet id, used for dedup with gateway_id and in the nonce, §3)
      17 .pki_encrypted: bool  (varint; DM signal, §3)
  -> Data (once decrypted)
       1 .portnum: PortNum     (varint; selects the decoder, §4)
       2 .payload: bytes       (portnum-specific payload, e.g. UTF-8 text for TEXT_MESSAGE_APP)
```

**Field numbers and wire types matter and are easy to get wrong.** Two
specifics that a hand-written parser (ADR-13) must get exactly right,
both confirmed against the public `mesh.proto` schema *and* against real
firmware traffic:

- `from`, `to`, and `id` are **`fixed32`** (4 little-endian bytes, wire
  type 5) — **not** varint-encoded `uint32`. Reading them as varints
  silently yields `0`, which in turn corrupts the AES-CTR nonce (§3,
  derived from `id` and `from`) and makes every decryption fail.
- `decoded` is field **4** and `encrypted` is field **5** — transposing
  them makes ciphertext look like a (malformed) plaintext `Data`
  message.

This project shipped both of those mistakes at once initially. A
symmetric encoder/decoder pair agreeing with each other is **not**
evidence of correctness — every round-trip unit test passed while real
traffic failed. `internal/decode/wireformat_test.go` therefore asserts
against hand-written wire bytes taken from the schema, never from this
package's own `Encode*` helpers.

- `MeshPacket.channel` is a **hash** derived from the channel name + PSK,
  used on the LoRa side for quick filtering — not how `brokerd` selects a
  PSK to attempt decryption with. `brokerd` matches a packet to a
  configured channel via the **topic's `{channel}` segment** (§1); the
  envelope's `channel_id` field carries the same value redundantly.
- Duplicate suppression: firmware already suppresses relay loops using
  `gateway_id` + packet `id` (`docs/architecture.md` §2). `brokerd`
  applies the same compound key to decide whether an incoming frame is a
  duplicate delivery vs. a genuinely distinct one — **implemented** in
  `internal/storage.IsDuplicate`, called from the storage worker
  (ADR-14). This is not hypothetical or only relevant to multi-board
  setups: a **single** board was observed re-delivering one identical
  packet three times at ~7-8 second intervals during this project's
  first board integration test. See `docs/storage-schema.md`'s
  `idx_raw_frames_dedup` index and `decode_status = duplicate`.
  A re-delivery is also recognised **at any age** when its payload is identical
  to the byte: a gateway re-publishes its queued packet on reconnect, which a
  brokerd restart triggers, and that gap is bounded by nothing (ADR-14).

## 3. Crypto

- Algorithm: **AES-256-CTR** with the channel's 32-byte PSK
  (`docs/firmware-config.md` §7).
- **Nonce**: a 16-byte IV built from `packet_id` (4 bytes, little-endian)
  + 4 zero bytes + `from`/sender node number (4 bytes, little-endian) +
  4 zero bytes (the last 4 bytes function as the CTR block counter,
  starting at 0). `internal/decode`'s nonce-construction function should
  still be isolated behind a unit-testable seam so any future firmware
  change is a one-line fix.
- **PKC-encrypted packets are out of scope for decoding**: Meshtastic
  ≥2.5 encrypts direct messages (DMs) with per-node public-key pairs, not
  the channel PSK. `brokerd` never holds node private keys, so any such
  packet is stored as an opaque `raw_frames` row only, with
  `decode_status = pki_encrypted`, and never attempted against
  `internal/decode`'s portnum registry. Two independent signals identify
  it, either sufficient alone: `ServiceEnvelope.channel_id` is the
  reserved literal string `"PKI"` (never a real configured channel name),
  and `MeshPacket.pki_encrypted` is set to `1`.

## 4. Portnum decoder registry

A pluggable registry keyed by `Data.portnum`. Every decoder writes a
`decoded_payloads` row (`docs/storage-schema.md` §2.1); the ones marked
below also write their own table or feed the outbound relay.

| Portnum | Status | Decodes to |
|---|---|---|
| `TEXT_MESSAGE_APP` (1) | implemented | UTF-8 payload -> `text_messages` row **and** `decoded_payloads` |
| `POSITION_APP` (3) | implemented | lat/lon (`latitude_i`/`longitude_i`) and `precision_bits`; feeds the relay's `coarse-position` rule (ADR-12). A no-fix position is normal traffic, recorded as `has_fix: false` |
| `NODEINFO_APP` (4) | implemented | Meshtastic `User`: id, long/short name, hw_model, role, flags. `macaddr` and `public_key` are deliberately not stored (the key's presence is recorded as a boolean) |
| `ROUTING_APP` (5) | implemented | `error_reason`, where **0 (NONE) is an acknowledgement**, not an absence of information; traceroute variants are recorded as present, not parsed |
| `TELEMETRY_APP` (67) | implemented | `DeviceMetrics` (battery, voltage, channel utilization, air-util-tx, uptime). Other metric groups are listed by name in `other_variants_present` so a new kind of telemetry is visible rather than silent |
| `MAP_REPORT_APP` (73) | pass-through | Not a channel message: plaintext, no channel segment, independent of any PSK (`docs/outbound-relay.md` §10.1). Registered without an interpreter so it is not counted as a decode failure |
| `NEIGHBORINFO_APP` (71) | not implemented | Reviewed and not worth adding (`docs/outbound-relay.md` §10.4) |

Any portnum without a registered decoder still gets its `raw_frames` row
(decrypted successfully, `decode_status = unhandled_portnum`) and no
`decoded_payloads` row — decode failure is only for actual decrypt/parse
errors (ADR-4), not for not-yet-implemented decoders.

## 5. Test vectors (`testdata/`)

- `testdata/broadcast_text_1.bin` + `.expected`,
  `testdata/broadcast_text_2.bin` + `.expected` — real captured
  ciphertext/plaintext pairs from the capture spike
  (`docs/runbook.md` §2).
- `testdata/dm_pki_1.observed` — a real captured DM, confirming §3's
  PKC/`"PKI"` scope limit.

**PSKs are never committed.** The capture channels were throwaway
channels, deleted after the spike, and their PSK was deliberately never
recorded anywhere — so the ciphertext in these fixtures is **permanently
undecryptable**. That is a deliberate trade-off, not an oversight, and it
determines what the fixtures can be used to assert.

### What `TestCaptureFixtures` asserts (no key material needed)

1. **Nonce derivation** — `DeriveNonce(packet_id, from_node)` matches the
   `nonce_hex` captured from the device. This is the highest-value
   assertion in the whole crypto path and it is pure ground truth: the
   expected value came off real firmware, not out of this codebase.
2. **Captured plaintext parses** — the firmware's own
   `expected_plaintext_data_protobuf_hex` parses to the expected portnum
   and text through the hand-written parser (ADR-13).
3. **Ciphertext/plaintext length equality** — the structural invariant of
   an AES-CTR pair, which catches a corrupted fixture.

### Where end-to-end decryption is verified instead

The ciphertext→plaintext step cannot be re-asserted from committed
fixtures (no key). It has been verified twice against real hardware
instead:

- during the capture spike, by decrypting these exact captures with the
  (then-live) channel PSK;
- **on the live deployment**, by decrypting a real message sent on the
  production channel end to end (board → MQTT/TLS → `brokerd` →
  `text_messages`). That test also caught two real wire-format bugs
  (§2) that no unit test had, which is the stronger argument for
  hardware verification over more fixtures.

Earlier revisions of this document required an environment variable
(`MESHTASTIC_TEST_PSK`) and mandated that the test **fail loudly** rather
than skip when it was unset. That rule made `make check` permanently
red once the capture channels were deleted, so it has been dropped: the
fixture test now always runs and needs no secret. The underlying
principle it was protecting — *never let a missing secret silently turn
into a passing test* — is satisfied more simply by not having any
secret-gated test at all.

If a new board/firmware version is ever added, re-run the capture
procedure in `docs/runbook.md` §2 and add fixtures here rather than
assuming this spec still holds unchanged. If you want end-to-end
decryption asserted in CI as well, capture from a channel whose PSK you
are willing to commit (a throwaway key protecting nothing), and say so
explicitly in the fixture's `psk_note`.
