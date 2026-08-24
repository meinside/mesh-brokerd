-- brokerd's complete schema (docs/storage-schema.md).
--
-- One file, applied with CREATE ... IF NOT EXISTS every time the database is
-- opened. There is no migration history and no version table: this project
-- has a single deployment, so a schema change means editing this file and
-- running the same ALTER against that one database by hand -- which is
-- cheaper than carrying a migration runner to do it once.
--
-- Nullable means "the frame did not state this", never 0 (ADR-15).

CREATE TABLE IF NOT EXISTS raw_frames (
    id              INTEGER PRIMARY KEY,
    received_at     TEXT    NOT NULL,   -- RFC 3339 UTC, e.g. 2025-01-01T00:00:00Z
    topic           TEXT    NOT NULL,   -- full MQTT topic as received
    mqtt_username   TEXT    NOT NULL,   -- the publishing account
    board_id        TEXT    NOT NULL,   -- derived from mqtt_username, free-form
    channel_segment TEXT    NOT NULL,   -- topic's {channel} segment, verbatim
    node_segment    TEXT,               -- topic's {node} segment, verbatim
    gateway_id      TEXT,               -- ServiceEnvelope.gateway_id, "!hex"
    packet_id       INTEGER,            -- MeshPacket.id
    from_node       INTEGER,            -- MeshPacket.from
    to_node         INTEGER,            -- MeshPacket.to
    payload         BLOB    NOT NULL,   -- raw MQTT payload bytes, unmodified
    decode_status   TEXT    NOT NULL,   -- see docs/storage-schema.md §1
    decode_version  INTEGER NOT NULL DEFAULT 1,

    -- MeshPacket fields describing how the packet was received.
    rx_snr          REAL,               -- field 8, float
    rx_rssi         INTEGER,            -- field 12, int32, negative in practice
    rx_time         INTEGER,            -- field 7, the gateway's own clock
    hop_limit       INTEGER,            -- field 9
    hop_start       INTEGER,            -- field 15
    want_ack        INTEGER,            -- field 10
    via_mqtt        INTEGER,            -- field 14
    priority        INTEGER,            -- field 11
    relay_node      INTEGER,            -- field 19

    -- Data fields; all NULL whenever the payload never became plaintext.
    portnum         INTEGER,            -- Data 1
    portnum_name    TEXT,               -- readable form of portnum
    want_response   INTEGER,            -- Data 3
    dest_node       INTEGER,            -- Data 4
    source_node     INTEGER,            -- Data 5
    request_id      INTEGER,            -- Data 6
    reply_id        INTEGER,            -- Data 7 (bitfield is field 9, not 7)
    bitfield        INTEGER             -- Data 9; bit 0 = OK_TO_MQTT
);

CREATE INDEX IF NOT EXISTS idx_raw_frames_received_at ON raw_frames(received_at);
CREATE INDEX IF NOT EXISTS idx_raw_frames_channel     ON raw_frames(channel_segment);
CREATE INDEX IF NOT EXISTS idx_raw_frames_from_node   ON raw_frames(from_node);
-- Deliberately NOT unique: a legitimate re-delivery much later must still be
-- storable, so duplicate suppression is a bounded-window lookup (ADR-14).
CREATE INDEX IF NOT EXISTS idx_raw_frames_dedup       ON raw_frames(gateway_id, packet_id);
CREATE INDEX IF NOT EXISTS idx_raw_frames_portnum     ON raw_frames(portnum, received_at);

CREATE TABLE IF NOT EXISTS text_messages (
    id              INTEGER PRIMARY KEY,
    raw_frame_id    INTEGER NOT NULL REFERENCES raw_frames(id),
    portnum         TEXT    NOT NULL,
    channel_name    TEXT,
    from_node       INTEGER NOT NULL,
    to_node         INTEGER,
    -- When brokerd received the frame: a copy of raw_frames.received_at, not
    -- a time any node stated. The copy is deliberate -- retention deletes from
    -- this table without joining raw_frames -- so do not "normalise" it away.
    -- What the packet itself stated is raw_frames.rx_time, and it stays there.
    received_at     TEXT    NOT NULL,
    text            TEXT    NOT NULL,
    decode_version  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_text_messages_raw_frame ON text_messages(raw_frame_id);
CREATE INDEX IF NOT EXISTS idx_text_messages_received_at ON text_messages(received_at);
CREATE INDEX IF NOT EXISTS idx_text_messages_from_node ON text_messages(from_node);

-- One row per frame whose payload a portnum decoder interpreted, with the
-- decoder's output as JSON. A table per portnum was rejected: a new portnum
-- then costs a decoder and nothing else.
CREATE TABLE IF NOT EXISTS decoded_payloads (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_frame_id   INTEGER NOT NULL REFERENCES raw_frames(id),
    portnum        INTEGER NOT NULL,
    portnum_name   TEXT    NOT NULL,   -- e.g. TELEMETRY_APP
    fields         TEXT    NOT NULL,   -- JSON; an absent key means "not stated"
    decode_version INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decoded_payloads_frame   ON decoded_payloads (raw_frame_id);
CREATE INDEX IF NOT EXISTS idx_decoded_payloads_portnum ON decoded_payloads (portnum, id);

-- node_names is what a node has said about itself in a NODEINFO_APP frame,
-- kept so a node id can be shown with the name its owner gave it.
--
-- A separate table rather than a query over decoded_payloads, for two reasons
-- measured on real traffic: retention deletes decoded_payloads, and NODEINFO
-- arrives a handful of times a month, so a derived lookup would lose every
-- name the first time the window passed. And a name is not stable -- one node
-- changed its long name mid-month -- so the current name has to be recorded
-- as such, with when it was first and last seen.
--
-- NULL means the frame did not state the field (ADR-15). Retention never
-- touches this table: it is one row per node, and its whole purpose is to
-- outlive the frame that taught it.
CREATE TABLE IF NOT EXISTS node_names (
  node_id     INTEGER PRIMARY KEY,
  long_name   TEXT,
  short_name  TEXT,
  hw_model    INTEGER,
  role        INTEGER,
  stated_id   TEXT,     -- User.id as the payload spelled it, for cross-checking
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  updates     INTEGER NOT NULL DEFAULT 1,  -- NODEINFO frames seen for this node
  renames     INTEGER NOT NULL DEFAULT 0   -- times long_name actually changed
);
