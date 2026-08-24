// Package decode implements brokerd's protocol layer: MQTT topic
// grammar, the ServiceEnvelope/MeshPacket/Data wire format, channel
// decryption, and the per-portnum decoder registry.
//
// Per ADR-13 (docs/adr.md), none of this imports or is generated from
// meshtastic/protobufs (GPL-3.0). The minimal protobuf wire-format
// reader in this file is a hand-written, general-purpose varint/tag
// parser — it knows nothing about Meshtastic's message shapes. The
// message-specific field layouts live in envelope.go, written directly
// against docs/protocol-spec.md.
package decode

import (
	"encoding/binary"
	"fmt"
)

// Protobuf wire types (part of the protobuf encoding specification
// itself, not anything specific to Meshtastic's schema).
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

// pbField is one decoded (field number, wire value) pair from a
// length-delimited protobuf message.
type pbField struct {
	Number  int
	Type    int
	Varint  uint64 // valid when Type == wireVarint
	Bytes   []byte // valid when Type == wireBytes
	Fixed32 uint32 // valid when Type == wireFixed32
	Fixed64 uint64 // valid when Type == wireFixed64
}

// parsePBFields walks a length-delimited protobuf message's raw bytes
// and returns every (field, value) pair found, in wire order. Repeated
// occurrences of the same field number are preserved in order (proto3's
// "last one wins" rule for singular fields is applied by callers via
// lastField, not here).
func parsePBFields(b []byte) ([]pbField, error) {
	var fields []pbField
	i := 0
	for i < len(b) {
		tag, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return nil, fmt.Errorf("decode: invalid varint tag at offset %d", i)
		}
		i += n

		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x7)

		switch wireType {
		case wireVarint:
			v, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, fmt.Errorf("decode: invalid varint value for field %d at offset %d", fieldNum, i)
			}
			fields = append(fields, pbField{Number: fieldNum, Type: wireVarint, Varint: v})
			i += n
		case wireBytes:
			ln, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, fmt.Errorf("decode: invalid length varint for field %d at offset %d", fieldNum, i)
			}
			i += n
			end := i + int(ln)
			if ln > uint64(len(b)) || end > len(b) || end < i {
				return nil, fmt.Errorf("decode: field %d length %d exceeds buffer", fieldNum, ln)
			}
			fields = append(fields, pbField{Number: fieldNum, Type: wireBytes, Bytes: b[i:end]})
			i = end
		case wireFixed64:
			if i+8 > len(b) {
				return nil, fmt.Errorf("decode: field %d fixed64 truncated", fieldNum)
			}
			fields = append(fields, pbField{Number: fieldNum, Type: wireFixed64, Fixed64: binary.LittleEndian.Uint64(b[i : i+8])})
			i += 8
		case wireFixed32:
			if i+4 > len(b) {
				return nil, fmt.Errorf("decode: field %d fixed32 truncated", fieldNum)
			}
			fields = append(fields, pbField{Number: fieldNum, Type: wireFixed32, Fixed32: binary.LittleEndian.Uint32(b[i : i+4])})
			i += 4
		default:
			return nil, fmt.Errorf("decode: unsupported wire type %d for field %d (groups are not used by Meshtastic's schema)", wireType, fieldNum)
		}
	}
	return fields, nil
}

// lastField returns the last occurrence of fieldNum in fields (proto3's
// "last singular field wins" rule), or ok=false if absent.
func lastField(fields []pbField, fieldNum int) (pbField, bool) {
	var found pbField
	ok := false
	for _, f := range fields {
		if f.Number == fieldNum {
			found = f
			ok = true
		}
	}
	return found, ok
}
