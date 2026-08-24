package decode

// Routing is the decoded payload of a ROUTING_APP packet. Field numbers
// are from the schema (meshtastic/mesh.proto's `message Routing`), read
// rather than generated (ADR-13):
//
//	1 route_request (RouteDiscovery)
//	2 route_reply   (RouteDiscovery)
//	3 error_reason  (Error enum, varint)
//
// A ROUTING_APP packet is how an ACK or a delivery failure comes back, so
// error_reason = 0 (NONE) is the common and *successful* case: it means
// "acknowledged", not "no information". The RouteDiscovery variants are
// recorded as present without being parsed — traceroute is not something
// brokerd interprets, and the bytes remain in raw_frames.
type Routing struct {
	ErrorReason    uint32
	HasErrorReason bool

	HasRouteRequest bool
	HasRouteReply   bool
}

const (
	feRoutingRouteRequest = 1
	feRoutingRouteReply   = 2
	feRoutingErrorReason  = 3
)

// decodeRouting implements PortNumRouting.
func decodeRouting(res *Result, payload []byte) error {
	fields, err := parsePBFields(payload)
	if err != nil {
		return err
	}

	r := &Routing{}
	if f, ok := lastField(fields, feRoutingErrorReason); ok {
		r.ErrorReason = uint32(f.Varint)
		r.HasErrorReason = true
	}
	if _, ok := lastField(fields, feRoutingRouteRequest); ok {
		r.HasRouteRequest = true
	}
	if _, ok := lastField(fields, feRoutingRouteReply); ok {
		r.HasRouteReply = true
	}
	res.Routing = r
	return nil
}
