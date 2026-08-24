package storage

import (
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// TestDeleteExpired_UsesOurArrivalTimeNotAnyStatedTime is the reason
// text_messages.received_at holds what it holds (docs/storage-schema.md §8.2).
//
// Retention deletes from text_messages by that column. A time the *packet*
// states is set by the sending node -- any node in radio range -- so if the
// column ever carried it, a node whose clock reads 1990 would have its messages
// deleted at the next prune however recently they arrived, and one reading 2030
// would keep them forever. A frame stating 1990 must not take its message with
// it.
func TestDeleteExpired_UsesOurArrivalTimeNotAnyStatedTime(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC()

	res := &decode.Result{
		Topic:          "msh/pvt/2/e/pvt/!11223344",
		ChannelSegment: "pvt",
		GatewayID:      "!11223344",
		PacketID:       0x5674c7f4,
		FromNode:       0x11223344,
		Status:         decode.StatusDecoded,
		Portnum:        decode.PortNumTextMessage,
		PacketParsed:   true,
		TextMessage:    &decode.TextMessage{Text: "arrived just now"},
		RxTime:         uint32(time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC).Unix()),
	}
	rawID, err := s.InsertRawFrame(res, "alpha", "alpha", []byte{0x01}, now)
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := s.InsertTextMessage(rawID, res, "pvt", now); err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}

	if _, _, err := s.DeleteExpired(30, 30); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM text_messages;`).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 1 {
		t.Error("a message that arrived seconds ago was deleted because its packet claimed 1990")
	}
}
