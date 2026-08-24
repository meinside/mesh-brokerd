# Storage Schema

The full SQLite schema `internal/storage` is written against.
Raw-frame-first (`docs/architecture.md` §3): every packet that reaches the
`OnPublish` hook gets a `raw_frames` row, unconditionally, before decode is
attempted (ADR-3/ADR-4, `docs/adr.md`). Decoded rows (`text_messages`, and
later `positions`/`telemetry`/`nodes`, `docs/protocol-spec.md` §4) are
derived, optional, and reprocessable.

## 1. `raw_frames`

```sql
CREATE TABLE raw_frames (
    id              INTEGER PRIMARY KEY,
    received_at     TEXT    NOT NULL,   -- RFC 3339 UTC, e.g. 2025-01-01T00:00:00Z
    topic           TEXT    NOT NULL,   -- full MQTT topic as received
    mqtt_username   TEXT    NOT NULL,   -- the publishing account, e.g. alpha
    board_id        TEXT    NOT NULL,   -- free-form string derived from mqtt_username,
                                         -- never an enum (docs/architecture.md §10.1)
    channel_segment TEXT    NOT NULL,   -- topic's {channel} segment, verbatim —
                                         -- opaque text; never parsed further
    node_segment    TEXT,               -- topic's {node} segment, verbatim, opaque
    gateway_id      TEXT,               -- ServiceEnvelope.gateway_id, "!hex" form
    packet_id       INTEGER,            -- MeshPacket.id
    from_node       INTEGER,            -- MeshPacket.from, if parseable
    to_node         INTEGER,            -- MeshPacket.to, if parseable
    payload         BLOB    NOT NULL,   -- the raw MQTT payload bytes, unmodified
    decode_status   TEXT    NOT NULL,   -- see status values below
    decode_version  INTEGER NOT NULL DEFAULT 1,

    -- ADR-15. Every one of these is nullable and
    -- NULL means "the frame did not state it", which is never the same fact
    -- as 0: rx_snr = 0.0 is a measurement of 0 dB, rx_snr IS NULL means the
    -- gateway generated the packet and never heard it over RF.
    rx_snr          REAL,               -- MeshPacket 8, float
    rx_rssi         INTEGER,            -- MeshPacket 12, int32, negative in practice
    rx_time         INTEGER,            -- MeshPacket 7, the gateway's own clock
    hop_limit       INTEGER,            -- MeshPacket 9
    hop_start       INTEGER,            -- MeshPacket 15
    want_ack        INTEGER,            -- MeshPacket 10
    via_mqtt        INTEGER,            -- MeshPacket 14
    priority        INTEGER,            -- MeshPacket 11
    relay_node      INTEGER,            -- MeshPacket 19
    portnum         INTEGER,            -- Data 1; NULL whenever the payload never became plaintext
    portnum_name    TEXT,               -- readable form of portnum
    want_response   INTEGER,            -- Data 3
    dest_node       INTEGER,            -- Data 4
    source_node     INTEGER,            -- Data 5
    request_id      INTEGER,            -- Data 6
    reply_id        INTEGER,            -- Data 7 (reply_id -- bitfield is field 9)
    bitfield        INTEGER             -- Data 9; bit 0 = OK_TO_MQTT
);
```

Field numbers above are from the schema, verified before use. Two are
traps: `rx_snr` is a **float** (wire type fixed32, not a varint), and
`Data` field 7 is `reply_id` — `bitfield` is field 9, and reading 7 as the
bitfield returns a confident, wrong zero.

`decode_status` values: `pending` (not yet attempted — should not persist
in practice, since decode happens synchronously in the storage worker),
`decoded` (a corresponding decoded row exists), `duplicate` (decrypted
and decoded fine, but an earlier delivery of the same
`(gateway_id, packet_id)` already produced the decoded row — ADR-14; the
raw frame is still kept, no decoded row is written, and no outbound
relay is attempted), `unknown_channel` (no PSK configured for
`channel_segment`), `decrypt_failed` (PSK configured but
decryption/parse failed — a real bug candidate, see ADR-4),
`pki_encrypted` (DM traffic, out of scope by design),
`unhandled_portnum` (decrypted fine, no decoder registered yet for that
portnum, `docs/protocol-spec.md` §4).

Note that a duplicate of a *failed* frame keeps its failure reason
(`decrypt_failed` etc.) rather than being relabelled `duplicate` — the
diagnostic is worth more than the duplicate flag, and no decoded row
would be written either way.

## 2. `text_messages`

```sql
CREATE TABLE text_messages (
    id              INTEGER PRIMARY KEY,
    raw_frame_id    INTEGER NOT NULL REFERENCES raw_frames(id),
    portnum         TEXT    NOT NULL,   -- 'TEXT_MESSAGE_APP' (kept as text, not an enum,
                                         -- for the same forward-compat reason as board_id)
    channel_name    TEXT,               -- resolved channel name from brokerd's config,
                                         -- when the lookup is name-based
    from_node       INTEGER NOT NULL,
    to_node         INTEGER,            -- NULL/broadcast address for broadcast packets
    received_at     TEXT    NOT NULL,   -- RFC 3339 UTC; a copy of raw_frames.received_at
                                         -- (see below -- it is not a time any node stated)
    text            TEXT    NOT NULL,
    decode_version  INTEGER NOT NULL DEFAULT 1
);
```

- One `raw_frames` row produces at most one `text_messages` row (1:1 for
  this portnum; other future portnums may be 1:many, e.g. telemetry with
  multiple metrics per packet).
- `decode_version` on both tables supports reprocessing: when the nonce
  derivation or channel-segment interpretation is corrected,
  a reprocessing job re-reads `raw_frames.payload` for rows with
  an older `decode_version`, re-attempts decode with the corrected logic,
  and either inserts/updates the decoded row or leaves `decode_status`
  updated to reflect the new outcome. This is also how
  `docs/firmware-config.md` §7's "adding a channel key later re-decodes
  already-stored raw frames" promise is implemented — filter
  `raw_frames` by `decode_status = 'unknown_channel'` and channel segment,
  then reprocess.

## 2.1. `decoded_payloads`

```sql
CREATE TABLE decoded_payloads (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_frame_id   INTEGER NOT NULL REFERENCES raw_frames(id),
    portnum        INTEGER NOT NULL,
    portnum_name   TEXT    NOT NULL,   -- e.g. TELEMETRY_APP
    fields         TEXT    NOT NULL,   -- JSON: whatever the portnum decoder understood
    decode_version INTEGER NOT NULL
);
```

One row per frame whose payload a decoder interpreted, text included (a
text frame writes both this and a `text_messages` row; `text_messages`
is unchanged and still the table to query for messages).

**Why JSON rather than a table per portnum**: a new portnum then costs a
decoder and nothing else — no schema change, no table, no query path. The
fields stay queryable:

```sql
SELECT json_extract(fields, '$.device_metrics.battery_level')
  FROM decoded_payloads WHERE portnum_name = 'TELEMETRY_APP'
  ORDER BY id DESC LIMIT 1;
```

**An absent key means the packet did not state it.** Decoders emit a key
only when the corresponding field was present, so a stored `0` is always a
real zero — the same rule as the nullable columns in §1, for the same
reason.

A portnum with no decoder writes **no row here**; its bytes are in
`raw_frames.payload` and its `decode_status` is `unhandled_portnum`
(ADR-4). This table therefore answers "what kinds of traffic arrived",
which nothing could before: 189 rows of `decode_status = 'decoded'` were
indistinguishable from each other.

## 3. Indexes

```sql
CREATE INDEX idx_raw_frames_received_at ON raw_frames(received_at);
CREATE INDEX idx_raw_frames_channel     ON raw_frames(channel_segment);
CREATE INDEX idx_raw_frames_from_node   ON raw_frames(from_node);
-- Dedup key for duplicate relay suppression (docs/protocol-spec.md §2).
-- Not UNIQUE: a genuine retransmission after a long gap is still valid
-- data, this index only makes the dedup lookup itself fast.
CREATE INDEX idx_raw_frames_dedup       ON raw_frames(gateway_id, packet_id);

CREATE INDEX idx_text_messages_raw_frame ON text_messages(raw_frame_id);
CREATE INDEX idx_text_messages_received_at ON text_messages(received_at);
CREATE INDEX idx_text_messages_from_node ON text_messages(from_node);
```

## 4. SQLite settings

- `PRAGMA journal_mode = WAL;` — allows the storage worker to write while
  monitoring endpoints (`docs/monitoring-api.md`) read concurrently.
- `PRAGMA busy_timeout = 5000;` — avoid immediate `SQLITE_BUSY` errors
  under brief write contention.
- `PRAGMA synchronous = NORMAL;` — the standard WAL-mode pairing; full
  `FULL` durability is not needed given raw frames are re-derivable from
  the mesh only during the retention window, not after.
- A single writer goroutine (the storage worker, ADR-3) avoids needing
  `SQLITE_BUSY` retry logic on the write path entirely; monitoring reads
  use a separate read-only connection.

## 5. Schema changes

The whole schema is one file, `internal/storage/schema.sql`, embedded with
`go:embed` and applied with `CREATE TABLE / CREATE INDEX IF NOT EXISTS` on
every `Open`. There is **no migration runner and no version table**.

That is a deliberate trade for a single-deployment project: a migration
framework exists to bring *other people's* databases forward, and there are
none. Changing the schema therefore means editing `schema.sql` and running
the same statement once against the live database by hand:

```sh
sqlite3 <data-dir>/brokerd.db 'ALTER TABLE raw_frames ADD COLUMN example INTEGER;'
```

Back up first with `.backup`, never `cp` (§6). Prefer additive changes —
new nullable columns and new tables need no data transformation, and
`IF NOT EXISTS` then makes a fresh database and the live one converge
without any version comparison.

If this ever ships to someone else's deployment, this section is the thing
that has to change first.

## 6. Retention and VACUUM

- Deletion queries (run periodically by an internal ticker, ADR-7):
  ```sql
  DELETE FROM raw_frames    WHERE received_at < :cutoff_raw;
  DELETE FROM text_messages WHERE received_at  < :cutoff_decoded;
  ```
  where `:cutoff_raw`/`:cutoff_decoded` are `now - retention.raw_frames_days`/
  `now - retention.decoded_days` respectively (skipped entirely when the
  corresponding setting is `0`, i.e. unlimited). Both settings default to
  **30 days** when absent from `config.json`; `0` has to be written
  explicitly to opt into unlimited retention (`docs/brokerd-config.md`).
- `text_messages` rows are deleted independently of their `raw_frames`
  parent (different retention window, §per ADR-7) — no cascading delete;
  a `text_messages` row can outlive or be outlived by its `raw_frames`
  row depending on which window is shorter.
- `VACUUM` is **not** run automatically on every deletion pass (it locks
  the whole database and rewrites the file). Run it manually or via a
  separate, infrequent scheduled task (e.g. weekly, during low-traffic
  hours), documented as a routine operation in `docs/runbook.md` §9.
- Backup: no automatic pre-deletion backup in v1 (ADR-7) — back up the
  whole SQLite file (`sqlite3 <path> ".backup <dest>"`, safe under WAL).
  Copying `brokerd.db` alone silently loses whatever is still in the
  `-wal` file: a plain `cp` of a live database dropped 40 of 204 rows
  on whatever independent schedule the operator chooses.

## 7. Reprocessing

```sh
mesh-brokerd -config <path> -reprocess dry-run   # reports, writes nothing
mesh-brokerd -config <path> -reprocess apply     # writes, after copying the database
```

Re-decodes every frame from `raw_frames.payload` and fills in what the
current decoder understands. This is what makes a column added later
meaningful for frames that arrived earlier — the bytes were always kept for
exactly this (ADR-3).

`decode_version` records which generation of decoder wrote a row
(`storage.DecodeVersion`); bump it when a decoder's output changes meaning.

Rules, and the reason for each:

| Rule | Why |
| --- | --- |
| `dry-run` writes nothing and reports what would change; an unrecognised mode is an error | The default has to be the harmless one, and a typo must not rewrite every row |
| `VACUUM INTO` copies the database before the first write | A bulk rewrite of every row must not be the only version that exists. `VACUUM INTO` is WAL-safe, unlike `cp` |
| `text_messages` is left alone | Retention may have deleted rows there deliberately; re-creating them would undo a deletion the operator asked for |
| No `decoded_payloads` row for a frame older than `retention.decoded_days` | Same reason. The raw columns are still updated: those are part of the raw record |
| A frame that still fails to decode keeps its `decode_status` | A stored diagnosis is worth more than a fresh guess |
| Duplicate suppression is **recomputed** with the live rule, not carried over | One rule in both paths is what keeps them from disagreeing. A real re-delivery stays `duplicate` and gains no decoded row (ADR-14) |
| Each frame decodes inside a `recover()` | One malformed payload must not abort a pass over hundreds of others |
| Re-running is idempotent | A second pass adds no second decoded row |

**`decode_status` after reprocessing means "decodable with today's keys and
decoders", not "what happened at the time".** That is the point, but it does
overwrite history, so every transition is printed. The first real run on this
deployment reported four kinds, each traceable to one change:

| Transition | Cause |
| --- | --- |
| `unhandled_portnum` -> `decoded` | Decoders that did not exist when those frames arrived |
| `duplicate` -> `decoded` | The packet-id-zero dedup bug (ADR-14's note) |
| `decoded` -> `duplicate` | Frames stored before duplicate suppression was implemented |
| `decrypt_failed` -> `decoded` | A channel key mismatch that was later corrected; today's key decrypts the frame |

## 8.1. What reprocessing refuses to do

`decode_status` after a pass means "decodable with today's keys and decoders",
not "what happened at the time" — with one exception, added after a real channel
key rotation:

**A frame stored as `decoded` is never downgraded.** It was decrypted with the
key in use then, and overwriting the row would replace a real portnum, SNR and
payload with NULLs that nothing can recover: the ciphertext is still stored, but
the key that opened it is gone. Such frames are listed as
`kept_because_no_longer_decodable` and left alone.

A dry run predicts what apply will do, including skipping decoded rows that
already exist. An earlier pass predicted 118 insertions and performed 1; the
prediction is the number an operator decides on, so it now checks the same
condition apply checks.

## 9. `node_names`

What a node has said about itself in a `NODEINFO_APP` frame, so a node id can be
shown with the name its owner gave it -- on the monitoring page and in a hook
payload.

| Column | Notes |
| --- | --- |
| `node_id` | Primary key, the packet's `from` |
| `long_name`, `short_name` | `NULL` when the frame did not state one |
| `hw_model`, `role` | `NULL` when not stated |
| `stated_id` | `User.id` as the payload spelled it, kept for cross-checking |
| `first_seen`, `last_seen` | RFC 3339 UTC |
| `updates` | NODEINFO frames seen for this node |
| `renames` | Times `long_name` actually changed |

Two measurements decided this is a table rather than a query over
`decoded_payloads`:

- **Retention deletes the frames.** NODEINFO arrived 9 times in the first
  month. A derived lookup would lose every name the first time the retention
  window passed, and the loss would read as "this node never introduced
  itself".
- **A name is not stable.** One node changed its long name mid-month. The
  current name is therefore recorded as current, with the first sighting kept
  and the change counted.

Retention never touches this table: it is one row per node, and outliving the
frame that taught it is the point.

**A name is normalised once, on the way in.** A name is arbitrary text typed by
whoever owns the radio, and three kinds of it are not names to a reader: leading
and trailing whitespace, control characters, and format characters such as
U+200B ZERO WIDTH SPACE, which is invisible while being a non-empty string.
Anything printable is kept, emoji and non-Latin text included. Doing this in one
function is what keeps the table, the in-memory cache, the page and a hook
payload from disagreeing about whether a node has a name at all -- the cache
used to hold the raw string while the column held the trimmed one, so the page
answered differently before and after a restart.

**An unstated name never erases a known one.** Protobuf omits an empty string,
so a NODEINFO frame carrying only a short name says nothing about the long one;
treating that as "cleared" would wipe the name every surface displays (ADR-15).
The cost is that a node which genuinely clears its name keeps the last one it
stated, because nothing on the wire distinguishes the two.

`User.id` agreed with the packet's `from` in all 9 observed frames, so `from` is
the key -- but the stated id is stored too, because a disagreement would mean
the name describes a different node than the one that sent it.

### 8.2. `text_messages.received_at`, and why it is not `sent_at`

The column was called `sent_at` and documented as "from the packet if present,
else falls back to `raw_frames.received_at`". No code ever implemented the first
half: every row's value equalled the parent frame's arrival time, in all 31 rows
of this deployment's history when it was checked.

It was renamed rather than made to match its name, because **retention deletes
from this table by this column**:

```sql
DELETE FROM text_messages WHERE received_at < :cutoff_decoded;
```

A time the packet states is set by the sending node — any node in radio range.
Had that value driven this delete, a node whose clock reads 1990 would have its
messages deleted at the next prune however recently they arrived, and one whose
clock reads 2030 would have them kept forever. The value deciding when our data
is deleted has to be our own observation.

What the packet stated is kept, unchanged, in `raw_frames.rx_time`, and the
monitoring page shows both times side by side with the difference named
(`queued 14m37s`, `node clock ahead 5m0s`). A message that stated no time shows a
dash there: an unstated value is never filled in with ours (ADR-15).

The copy of `raw_frames.received_at` is deliberate — it lets retention delete
from this table without a join — so it is not redundancy to normalise away.

A database created before the rename does **not** open: the schema indexes
`received_at`, and applying it against a table that still has `sent_at` fails
with `no such column`. A one-off guarded `ALTER TABLE` carried this deployment
across and was then deleted, because a permanent one would have been the
migration runner ADR-16 declined. Anything still on the old name is brought
forward the way ADR-16 prescribes for every schema change — by hand, once:

```sql
DROP INDEX IF EXISTS idx_text_messages_sent_at;
ALTER TABLE text_messages RENAME COLUMN sent_at TO received_at;
```
