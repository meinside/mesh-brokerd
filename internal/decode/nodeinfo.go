package decode

// NodeInfo is the decoded payload of a NODEINFO_APP packet: Meshtastic's
// `User` message. Field numbers are from the schema (meshtastic/mesh.proto's
// `message User`), read rather than generated (ADR-13):
//
//	1 id (string)          5 hw_model (enum varint)
//	2 long_name (string)   6 is_licensed (bool)
//	3 short_name (string)  7 role (enum varint)
//	4 macaddr (bytes)      8 public_key (bytes)
//	                       9 is_unmessagable (bool)
//
// macaddr and public_key are deliberately not modelled: the MAC address is
// a hardware identifier brokerd has no use for, and the public key is
// already stored in the raw frame if it is ever needed. Everything parsed
// here is a self-declared name or capability, not a measurement.
type NodeInfo struct {
	ID        string
	LongName  string
	ShortName string

	HWModel    uint32
	HasHWModel bool
	Role       uint32
	HasRole    bool

	IsLicensed     bool
	IsUnmessagable bool
	HasPublicKey   bool
}

const (
	feUserID             = 1
	feUserLongName       = 2
	feUserShortName      = 3
	feUserHWModel        = 5
	feUserIsLicensed     = 6
	feUserRole           = 7
	feUserPublicKey      = 8
	feUserIsUnmessagable = 9
)

// decodeNodeInfo implements PortNumNodeInfo.
func decodeNodeInfo(res *Result, payload []byte) error {
	fields, err := parsePBFields(payload)
	if err != nil {
		return err
	}

	ni := &NodeInfo{}
	if f, ok := lastField(fields, feUserID); ok {
		ni.ID = string(f.Bytes)
	}
	if f, ok := lastField(fields, feUserLongName); ok {
		ni.LongName = string(f.Bytes)
	}
	if f, ok := lastField(fields, feUserShortName); ok {
		ni.ShortName = string(f.Bytes)
	}
	if f, ok := lastField(fields, feUserHWModel); ok {
		ni.HWModel = uint32(f.Varint)
		ni.HasHWModel = true
	}
	if f, ok := lastField(fields, feUserRole); ok {
		ni.Role = uint32(f.Varint)
		ni.HasRole = true
	}
	if f, ok := lastField(fields, feUserIsLicensed); ok {
		ni.IsLicensed = f.Varint != 0
	}
	if f, ok := lastField(fields, feUserIsUnmessagable); ok {
		ni.IsUnmessagable = f.Varint != 0
	}
	if f, ok := lastField(fields, feUserPublicKey); ok {
		ni.HasPublicKey = len(f.Bytes) > 0
	}
	res.NodeInfo = ni
	return nil
}
