package decode

import "testing"

func TestDefaultChannelPSK_AES128(t *testing.T) {
	if len(DefaultChannelPSK) != 16 {
		t.Fatalf("DefaultChannelPSK has %d bytes, want 16 (AES-128, per firmware source)", len(DefaultChannelPSK))
	}
}

func TestCryptCTR_AcceptsAES128Key(t *testing.T) {
	nonce := DeriveNonce(1, 2)
	plaintext := []byte("hello, default channel")

	ciphertext, err := CryptCTR(DefaultChannelPSK[:], nonce, plaintext)
	if err != nil {
		t.Fatalf("CryptCTR with a 16-byte key: %v", err)
	}

	roundTrip, err := CryptCTR(DefaultChannelPSK[:], nonce, ciphertext)
	if err != nil {
		t.Fatalf("CryptCTR (decrypt): %v", err)
	}
	if string(roundTrip) != string(plaintext) {
		t.Errorf("round trip = %q, want %q", roundTrip, plaintext)
	}
}

func TestChannelHash(t *testing.T) {
	// Sanity check against the firmware's own algorithm
	// (xorHash(name) ^ xorHash(key)), not a specific captured value --
	// this project has not captured a real hash for the *default*
	// channel specifically, only for custom channels via the topic
	// segment (which does not carry the hash at all).
	h1 := ChannelHash("LongFast", DefaultChannelPSK[:])
	h2 := ChannelHash("LongFast", DefaultChannelPSK[:])
	if h1 != h2 {
		t.Fatal("ChannelHash is not deterministic for the same inputs")
	}

	h3 := ChannelHash("Different", DefaultChannelPSK[:])
	if h1 == h3 {
		t.Error("ChannelHash did not change when the channel name changed (extremely unlikely by chance, check the XOR logic)")
	}
}
