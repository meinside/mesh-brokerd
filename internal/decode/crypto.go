package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// PSKSize is the required channel PSK length for this project's own
// configured channels (docs/protocol-spec.md section 3, ADR-11):
// AES-256, so exactly 32 bytes. This is a project convention
// (internal/config validates every configured channel PSK is exactly
// this length) -- it is not a protocol-wide limit. Meshtastic's own
// well-known *public* default channel actually uses a 16-byte
// (AES-128) key -- see DefaultChannelPSK below -- which is why
// CryptCTR itself accepts a variable-length key rather than
// [PSKSize]byte.
const PSKSize = 32

// DefaultChannelPSK is Meshtastic's own well-known key for the public
// default channel every device powers up on (the "AQ==" / single-byte
// PSK shorthand, index 1) -- confirmed directly from firmware source
// (src/mesh/Channels.h's defaultpsk constant, comment: "16 bytes of
// random PSK for our _public_ default channel that all devices power
// up on (AES128)"). This is a fixed, publicly known protocol constant,
// not a secret -- there is nothing to protect by keeping it out of
// this file (docs/outbound-relay.md section 6's psk: "default"
// sentinel resolves to this).
var DefaultChannelPSK = [16]byte{
	0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
	0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
}

// DeriveNonce builds the 16-byte AES-CTR IV Meshtastic uses for a
// channel-encrypted packet (docs/protocol-spec.md section 3, confirmed
// against real captures in testdata/): packetID (4 bytes
// little-endian) + 4 zero bytes + fromNode (4 bytes little-endian) + 4
// zero bytes. The trailing 4 bytes double as the CTR block counter,
// starting at 0.
//
// Kept as its own function (rather than inlined into the cipher call)
// so a future firmware change to this derivation is a one-line fix,
// per docs/protocol-spec.md section 3.
func DeriveNonce(packetID, fromNode uint32) [16]byte {
	var nonce [16]byte
	binary.LittleEndian.PutUint32(nonce[0:4], packetID)
	// nonce[4:8] stays zero.
	binary.LittleEndian.PutUint32(nonce[8:12], fromNode)
	// nonce[12:16] stays zero (CTR block counter).
	return nonce
}

// CryptCTR runs AES-CTR over in using key+nonce, returning the result.
// key must be 16, 24, or 32 bytes (AES-128/192/256 respectively --
// this project's own channels are always 32 bytes per ADR-11, but
// Meshtastic's public default channel uses a 16-byte key, so this
// function does not assume a fixed length). CTR is a symmetric stream
// cipher (the keystream is XORed with the input either direction), so
// this same function both decrypts a channel's own inbound traffic
// (internal/decode) and encrypts outbound relay traffic
// (docs/outbound-relay.md section 6) -- one engine, two callers, per
// ADR-12's consequences.
func CryptCTR(key []byte, nonce [16]byte, in []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("decode: AES key setup: %w", err)
	}
	stream := cipher.NewCTR(block, nonce[:])
	out := make([]byte, len(in))
	stream.XORKeyStream(out, in)
	return out, nil
}

// DecryptChannelPacket decrypts a MeshPacket's Encrypted field with the
// given channel PSK, returning the plaintext Data bytes (still needing
// ParseData). Returns an error if key/nonce setup fails; it does not
// itself validate that the result is well-formed protobuf -- callers
// distinguish decrypt_failed from parse_failed (ADR-4) by attempting
// ParseData separately.
func DecryptChannelPacket(psk []byte, packetID, fromNode uint32, ciphertext []byte) ([]byte, error) {
	nonce := DeriveNonce(packetID, fromNode)
	return CryptCTR(psk, nonce, ciphertext)
}

// ChannelHash computes the (0-255) channel hash the firmware uses on
// the LoRa side for quick filtering (docs/protocol-spec.md section 2:
// MeshPacket.channel) -- confirmed directly from firmware source
// (src/mesh/Channels.cpp's generateHash): XOR of the channel name's
// bytes, XORed again with the (already-expanded, if it was a
// short-form PSK) key's bytes. Needed by the outbound relay
// (docs/outbound-relay.md section 5) so consumers that filter on the
// hash rather than the topic string still accept a relayed packet.
func ChannelHash(name string, psk []byte) byte {
	var h byte
	for _, c := range []byte(name) {
		h ^= c
	}
	for _, b := range psk {
		h ^= b
	}
	return h
}
