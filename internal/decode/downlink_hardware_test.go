//go:build hardware

package decode

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
)

// TestManualDownlink_PublishTextToPrivateChannel publishes one properly
// encrypted TEXT_MESSAGE_APP packet onto the private channel of a LIVE
// brokerd, exactly as a Meshtastic gateway would, so that the
// broker -> board downlink path can be verified without physical access to
// the board at the other site.
//
// This is the first test behind the `hardware` build tag: it needs a
// running brokerd, real board credentials, the real channel PSK, and a
// board at the far end whose companion app an operator is watching. It is
// therefore excluded from `make check`, while CI still type-checks it.
//
// Why it exists: verifying cross-site downlink otherwise requires being at
// both sites at once. A message sent from home does not tell you whether
// the office board received it if you are not at the office; publishing
// from the server does, because the operator only has to watch one end.
//
// Run it as:
//
//	CGO_ENABLED=1 go test -tags hardware ./internal/decode/... \
//	  -run TestManualDownlink_PublishTextToPrivateChannel -v
//
// with these set (source the real .env for the PSK):
//
//	BROKERD_DOWNLINK_BROKER   ssl://<host>:8883
//	BROKERD_DOWNLINK_USER     an account from config.json's boards[]
//	BROKERD_DOWNLINK_PASS     that account's password (NOT the hash)
//	BROKERD_DOWNLINK_CHANNEL  the private channel name
//	BROKERD_DOWNLINK_PSK      that channel's base64 PSK
//	BROKERD_DOWNLINK_FROM     sender node number, decimal
//	BROKERD_DOWNLINK_TEXT     optional; message body
//
// The packet is addressed to the broadcast node (0xFFFFFFFF) on the given
// channel, so every board with that channel and downlink_enabled should
// surface it.
func TestManualDownlink_PublishTextToPrivateChannel(t *testing.T) {
	env := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			// Fail rather than skip: a test that quietly skips when
			// unconfigured reports success for work it never did
			// (docs/protocol-spec.md §5).
			t.Fatalf("%s is not set — this test must fail, not skip", key)
		}
		return v
	}

	broker := env("BROKERD_DOWNLINK_BROKER")
	user := env("BROKERD_DOWNLINK_USER")
	pass := env("BROKERD_DOWNLINK_PASS")
	channel := env("BROKERD_DOWNLINK_CHANNEL")
	pskB64 := env("BROKERD_DOWNLINK_PSK")
	fromStr := env("BROKERD_DOWNLINK_FROM")

	text := os.Getenv("BROKERD_DOWNLINK_TEXT")
	if text == "" {
		text = fmt.Sprintf("downlink test %s", time.Now().Format("15:04:05"))
	}

	psk, err := base64.StdEncoding.DecodeString(pskB64)
	if err != nil {
		t.Fatalf("decoding BROKERD_DOWNLINK_PSK: %v", err)
	}
	if len(psk) != PSKSize {
		t.Fatalf("PSK is %d bytes, want %d", len(psk), PSKSize)
	}

	var from uint32
	if _, err := fmt.Sscanf(fromStr, "%d", &from); err != nil {
		t.Fatalf("parsing BROKERD_DOWNLINK_FROM %q: %v", fromStr, err)
	}

	var idb [4]byte
	if _, err := rand.Read(idb[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	// Meshtastic packet IDs are non-zero; the high bit keeps it clear of
	// the small ids the firmware itself hands out.
	packetID := binary.LittleEndian.Uint32(idb[:]) | 0x80000000

	plain := EncodeData(PortNumTextMessage, []byte(text))
	nonce := DeriveNonce(packetID, from)
	ciphertext, err := CryptCTR(psk, nonce, plain)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}

	// Round-trip through this package's own decoder before publishing, so
	// a malformed packet fails here rather than looking like a downlink
	// problem on the board. This is a sanity check on the encoding, NOT a
	// wire-format assertion (never assert wire format against
	// this codebase's own encoder).
	back, err := DecryptChannelPacket(psk, packetID, from, ciphertext)
	if err != nil {
		t.Fatalf("decrypting what we just encrypted: %v", err)
	}
	data, err := ParseData(back)
	if err != nil {
		t.Fatalf("parsing what we just encoded: %v", err)
	}
	if got := string(data.Payload); got != text {
		t.Fatalf("round trip changed the payload: %q != %q", got, text)
	}

	gatewayID := fmt.Sprintf("!%08x", from)
	packet := EncodeMeshPacket(MeshPacketFields{From: from, To: 0xFFFFFFFF, ID: packetID, ChannelHash: ChannelHash(channel, psk), Encrypted: ciphertext})
	envelope := EncodeServiceEnvelope(packet, channel, gatewayID)
	topic := fmt.Sprintf("msh/pvt/2/e/%s/%s", channel, gatewayID)

	opts := paho.NewClientOptions().AddBroker(broker).
		SetUsername(user).SetPassword(pass).
		SetClientID("brokerd-downlink-test").
		SetConnectTimeout(10 * time.Second).
		SetAutoReconnect(false)
	client := paho.NewClient(opts)

	tok := client.Connect()
	if !tok.WaitTimeout(15 * time.Second) {
		t.Fatal("connect timed out")
	}
	if err := tok.Error(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(200)

	pub := client.Publish(topic, 0, false, envelope)
	if !pub.WaitTimeout(10 * time.Second) {
		t.Fatal("publish timed out")
	}
	if err := pub.Error(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	t.Logf("published %q to %s (packet id 0x%08x, %d bytes)", text, topic, packetID, len(envelope))
	t.Log("now check the far-side board's companion app; brokerd should also have stored this in text_messages")
}
