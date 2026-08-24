# Hardware — Board Requirements and the Current Instance (Heltec V4)

This document has two parts: (1) the **general requirement set** any board
must satisfy to participate in this project's architecture, and (2) the
characteristics of the **specific hardware currently deployed** (two
Heltec V4 units). Part (1) is what makes the architecture in
`docs/architecture.md` independent of any one board model —
see `docs/architecture.md` §10.4 for why this separation exists and what
it enables (mixing board models across sites, swapping a board later
without redesigning anything).

## 1. General board requirements (architecture-level, board-agnostic)

Any board used at either site must satisfy all of the following. None of
them name a specific manufacturer/chipset — they're the actual properties
`brokerd`'s design (`docs/architecture.md`) and the MQTT bridge
(`docs/architecture.md` §2) depend on:

| Requirement | Why it's required | Notes |
|---|---|---|
| Runs official Meshtastic firmware with **WiFi support, or a serial↔MQTT proxy path** | The board must reach `brokerd` over the internet (`docs/architecture.md` §4) — either directly over its own WiFi, or by tunneling its MQTT client over USB serial to a permanently attached, internet-connected computer running `cmd/mshserial-mqtt-proxy` (`docs/architecture.md` §5, §10.4) | Meshtastic's own supported-device list is the filter for firmware/WiFi support — check `flasher.meshtastic.org` or the device hardware page. The serial-proxy path additionally needs `mqtt.proxy_to_client_enabled` support and a computer that's up as long as that board needs to stay bridged |
| Firmware's **MQTT module** supports `uplink_enabled`/`downlink_enabled` on a channel | This is the actual bridging mechanism (`docs/architecture.md` §2) — a WiFi-only board without MQTT module support cannot gateway anything to `brokerd` | Supported on essentially all current Meshtastic firmware targets; verify for boards outside the mainline device list |
| Firmware's companion-app transport (`network` module, TCP 4403) works over WiFi | Local companion-app access (`docs/architecture.md` §6) | Port `4403` is a firmware constant, not board-specific |
| A LoRa transceiver Meshtastic firmware supports for the target region (`lora.region`, `docs/firmware-config.md` §4) | Needed for any *local* mesh a board might still serve, and because Meshtastic requires a radio to run at all — but note this project's cross-site link is over MQTT, not LoRa (`docs/architecture.md` §2), so radio choice does not affect cross-site behavior | SX1262/SX1268/RFM95 etc. — whatever the chosen board ships |
| USB (serial or USB-C) power **or** an equivalent constant power source | Both boards run on constant power, no battery (`docs/firmware-config.md` §1) | Exact connector is irrelevant to the architecture |

> **Market note (as of this writing): WiFi is increasingly gateway-only
> hardware, not a given on new boards.** Meshtastic's current supported-
> device list (`meshtastic.org/docs/hardware/devices`) shows a clear split
> by chipset: most new **nRF52840-based** boards — aimed at handheld/
> battery/solar use (WisMesh Pocket/Tag/Repeater, RAK4631, ThinkNode M1/M3/
> M4/M6, Wio Tracker L1, SenseCAP Solar Node, T-Echo, etc.) — have **no
> WiFi radio at all**, only BLE, because dropping WiFi is a large part of
> how they hit multi-day/solar power budgets. WiFi is still shipped, but
> mainly on **ESP32/ESP32-S3-based** boards explicitly positioned as base-
> station/MQTT-gateway hardware (WisMesh WiFi MQTT Gateway, RAK3312,
> ThinkNode M2/M5/M7, T-Deck series, T-Lora Pager, Heltec LoRa32 V3,
> Station G2). In other words: this is not "WiFi support is disappearing
> across the board," it's "WiFi is being deliberately reserved for the
> mains-powered gateway role this project actually needs" — which
> narrows, but does not eliminate, the pool of boards satisfying this
> table's first requirement. Re-check the current device list against
> this requirement set before choosing a replacement/additional board.
>
> **This is exactly why the WiFi requirement above now has a second
> satisfying path**: a WiFi-less board can still participate via the
> serial↔MQTT proxy CLI (`docs/architecture.md` §5, §10.4), reusing the
> firmware's own `mqtt.proxy_to_client_enabled` mode
> (`docs/firmware-config.md` §8's F1) through a permanently attached,
> internet-connected computer — at the cost of that computer becoming an
> additional single point of failure for that site
> (`docs/architecture.md` §7).

**Explicitly not required by the architecture**, even though the current
hardware happens to have them — do not assume these when adding a
different board model:

- A specific MCU/chipset (ESP32-S3 today; the protocol/storage layers in
  `docs/protocol-spec.md` operate on Meshtastic's protobufs, not on
  anything chipset-specific).
- GPS/GNSS presence or absence — this is a per-board, per-unit hardware
  fact (`position.gps_mode` is set per board in `docs/firmware-config.md`
  §5, not assumed project-wide).
- BLE/WiFi mutual exclusivity — this happens to be true for ESP32 (see
  §3 below) but is **not a Meshtastic-wide guarantee**. A non-ESP32 board
  (e.g. nRF52-based) may support BLE and WiFi simultaneously. Any
  document that states "BLE is unavailable while WiFi is on" is stating
  an ESP32-specific fact, not an architectural assumption — verify this
  per board model before relying on it (`docs/runbook.md` §7's serial
  fallback exists specifically because this fact holds for the *current*
  hardware; it may not need to for a different board).
- A specific USB-to-UART bridge chip (CP210x/CH9102 today) — a different
  board may use a different chip requiring a different driver
  (`docs/runbook.md`'s serial prerequisite section).

## 2. Current hardware instance: Heltec V4 (WiFi LoRa 32 V4)

Both boards deployed today are Heltec V4 units, chosen because they
satisfy §1 and were already on hand. Nothing below is an architectural
requirement — it's a record of what the current hardware happens to be,
kept so its specific quirks (driver names, exact BLE behavior, output
power) are documented somewhere. Treat the manufacturer's datasheet as
the primary source for detailed electrical specs.

### 2.1. Confirmed facts

- MCU: ESP32-S3(R2) — built-in WiFi + Bluetooth 5 (LE).
- LoRa transceiver: SX1262.
- OLED: 0.96" (a protected version, improved in the V4).
- USB: USB-C connector; USB-to-UART bridge is CP210x or CH9102 depending
  on revision (`docs/runbook.md`'s serial prerequisite section).
- GNSS (GPS): **not built in by default; it's an add-on module (e.g. an L76
  GNSS Module) on this product line.** The two units in use are without a
  GPS module attached → reflected as `position.gps_mode = NOT_PRESENT` in
  the Position settings of `docs/firmware-config.md` for these two boards
  specifically (not a project-wide rule — see §1).
- LoRa output: 28±1 dBm per the manufacturer's materials (may vary by
  revision; the exact figure should be re-confirmed against the datasheet
  for the actual revision in use).

### 2.2. Meshtastic support status

- **Confirmed**: the Meshtastic web flasher (flasher.meshtastic.org) shows
  a supported latest firmware image for the Heltec V4. The risk of the
  board simply not being supported (which would break the whole premise)
  has been resolved.
- It may still be treated as Beta-tier support. Record the actual flashed
  firmware version string in `docs/firmware-config.md` §1 once provisioned
  (not recorded yet).

### 2.3. Characteristics that affect this project (ESP32-specific — see §1's caveats before generalizing any of these to a future board)

| Characteristic | Impact |
|---|---|
| WiFi and BLE cannot be used at the same time (ESP32-specific behavior, §1) | The companion app uses WiFi/TCP (4403) instead (see `docs/architecture.md`) |
| USB-C | Enables constant power without a battery → the basis for the office board's power strategy |
| No GNSS on these two units | `position.gps_mode = NOT_PRESENT` for these two boards |
| SX1262 + a 5–10 km urban distance | Direct LoRa mesh is impossible → an MQTT bridge was adopted (`docs/architecture.md` §2) — this conclusion holds for *any* board choice, since it's a distance/RF-physics argument, not specific to SX1262 |

