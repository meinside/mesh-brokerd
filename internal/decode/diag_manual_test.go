//go:build diag

package decode

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestDiagStoredFrame is a temporary diagnostic (build tag: diag) that
// reads the newest raw_frames payload from a real brokerd database and
// reports why decoding failed, without ever printing key material.
//
//	CGO_ENABLED=1 go test -tags diag ./internal/decode/... -run TestDiagStoredFrame -v
func TestDiagStoredFrame(t *testing.T) {
	dbPath := os.Getenv("DIAG_DB")
	if dbPath == "" {
		t.Fatal("DIAG_DB not set")
	}
	pskB64 := os.Getenv("DIAG_PSK")
	if pskB64 == "" {
		t.Fatal("DIAG_PSK not set")
	}
	configuredPSK, err := base64.StdEncoding.DecodeString(pskB64)
	if err != nil {
		t.Fatalf("DIAG_PSK is not valid base64: %v", err)
	}
	t.Logf("configured PSK length: %d bytes", len(configuredPSK))

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var topic string
	var payload []byte
	// DIAG_FRAME_ID selects one specific raw_frames row; without it the
	// newest is used. Needed because the frame worth inspecting is often
	// not the latest one (a position packet followed by two NodeInfo
	// replies, for instance).
	var row *sql.Row
	if id := os.Getenv("DIAG_FRAME_ID"); id != "" {
		t.Logf("inspecting raw_frames.id = %s", id)
		row = db.QueryRow(`SELECT topic, payload FROM raw_frames WHERE id = ?;`, id)
	} else {
		row = db.QueryRow(`SELECT topic, payload FROM raw_frames ORDER BY id DESC LIMIT 1;`)
	}
	if err := row.Scan(&topic, &payload); err != nil {
		t.Fatalf("read newest raw_frame: %v", err)
	}
	t.Logf("topic: %s", topic)
	t.Logf("payload length: %d bytes", len(payload))

	env, err := ParseServiceEnvelope(payload)
	if err != nil {
		t.Fatalf("ParseServiceEnvelope failed: %v", err)
	}
	t.Logf("envelope channel_id=%q gateway_id=%q", env.ChannelID, env.GatewayID)

	mp, err := ParseMeshPacket(env.PacketBytes)
	if err != nil {
		t.Fatalf("ParseMeshPacket failed: %v", err)
	}
	t.Logf("packet id=%#x from=%#x to=%#x pki_encrypted=%v encrypted_len=%d decoded_len=%d",
		mp.ID, mp.From, mp.To, mp.PKIEncrypted, len(mp.Encrypted), len(mp.Decoded))

	if mp.Encrypted == nil {
		t.Fatal("packet has no Encrypted field (nothing to decrypt)")
	}

	nonce := DeriveNonce(mp.ID, mp.From)
	t.Logf("derived nonce: %s", hex.EncodeToString(nonce[:]))

	// Attempt 1: the PSK brokerd is configured with.
	tryDecrypt(t, "configured PSK", configuredPSK, nonce, mp.Encrypted)

	// Attempt 2: Meshtastic's well-known default channel PSK -- if THIS
	// one parses, the board's channel is still on the default key (i.e.
	// the --ch-set psk step did not take effect).
	tryDecrypt(t, "Meshtastic default PSK (AQ==)", DefaultChannelPSK[:], nonce, mp.Encrypted)
}

func tryDecrypt(t *testing.T, label string, psk []byte, nonce [16]byte, ciphertext []byte) {
	t.Helper()
	plain, err := CryptCTR(psk, nonce, ciphertext)
	if err != nil {
		t.Logf("[%s] CryptCTR error: %v", label, err)
		return
	}
	data, err := ParseData(plain)
	if err != nil {
		t.Logf("[%s] -> decrypted bytes do NOT parse as Data protobuf (wrong key): %v", label, err)
		return
	}
	t.Logf("[%s] -> SUCCESS: portnum=%d payload=%q", label, data.Portnum, string(data.Payload))
}

// TestDiagStoredBitfield reports, for one stored frame, whether the
// sender's Data.bitfield carried BITFIELD_OK_TO_MQTT_MASK -- the bit a
// gateway checks before uplinking another node's packet
// (docs/firmware-config.md section 16).
//
// The bit is set by the *sending* node at encode time
// (firmware src/mesh/Router.cpp, perhapsEncode: has_bitfield = true;
// bitfield |= config.lora.config_ok_to_mqtt << 0), so reading it from a
// stored frame says what that node's setting was at that moment -- which
// is otherwise unknowable after the fact, since `--info` omits the
// default and shows only the present value.
//
//	DIAG_DB=/path/brokerd.db DIAG_PSK=<base64> DIAG_FRAME_ID=74 \
//	  CGO_ENABLED=1 go test -tags diag ./internal/decode/... -run TestDiagStoredBitfield -v
func TestDiagStoredBitfield(t *testing.T) {
	dbPath := os.Getenv("DIAG_DB")
	pskB64 := os.Getenv("DIAG_PSK")
	frameID := os.Getenv("DIAG_FRAME_ID")
	if dbPath == "" || pskB64 == "" || frameID == "" {
		t.Fatal("DIAG_DB, DIAG_PSK and DIAG_FRAME_ID must all be set")
	}
	psk, err := base64.StdEncoding.DecodeString(pskB64)
	if err != nil {
		t.Fatalf("decoding DIAG_PSK: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("opening %s: %v", dbPath, err)
	}
	defer func() { _ = db.Close() }()

	var payload []byte
	var topic string
	if err := db.QueryRow(
		`SELECT topic, payload FROM raw_frames WHERE id = ?;`, frameID,
	).Scan(&topic, &payload); err != nil {
		t.Fatalf("reading frame %s: %v", frameID, err)
	}

	env, err := ParseServiceEnvelope(payload)
	if err != nil {
		t.Fatalf("ParseServiceEnvelope: %v", err)
	}
	pkt, err := ParseMeshPacket(env.PacketBytes)
	if err != nil {
		t.Fatalf("ParseMeshPacket: %v", err)
	}

	data := pkt.Decoded
	if len(data) == 0 {
		nonce := DeriveNonce(pkt.ID, pkt.From)
		plain, err := CryptCTR(psk, nonce, pkt.Encrypted)
		if err != nil {
			t.Fatalf("CryptCTR: %v", err)
		}
		data = plain
	}

	t.Logf("frame %s topic=%s from=0x%08x id=%d", frameID, topic, pkt.From, pkt.ID)
	t.Logf("Data bytes: %s", hex.EncodeToString(data))

	// Data.bitfield is field 9, varint (checked against
	// meshtastic/protobufs' mesh.proto -- field 7 is reply_id, a fixed32,
	// which is what an earlier guess at "field 7" actually read).
	fields, err := parsePBFields(data)
	if err != nil {
		t.Fatalf("parsePBFields on Data: %v", err)
	}
	bf, has := lastField(fields, 9)
	bitfield := bf.Varint
	if !has {
		t.Logf("RESULT: no bitfield present -> a gateway treats this as"+
			" 'not OK to MQTT' (dontUplink = !has_bitfield || !bit), frame=%s", frameID)
		return
	}
	t.Logf("RESULT: bitfield=%d (0b%b) OK_TO_MQTT=%v WANT_RESPONSE=%v",
		bitfield, bitfield, bitfield&0x1 != 0, bitfield&0x2 != 0)
}
