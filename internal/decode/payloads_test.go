package decode

import "testing"

// All byte literals below are written by hand from the schema
// (meshtastic/mesh.proto's User and Routing, meshtastic/telemetry.proto's
// Telemetry and DeviceMetrics), never produced by this package -- a decoder
// and an encoder that share a wrong field number agree with each other and
// pass every round-trip test (docs/protocol-spec.md §5).

// TestDecodeNodeInfo_GroundTruth pins User's field numbers. long_name is
// field 2 and short_name field 3; swapping them yields two plausible
// strings and no error at all, so only an explicit assertion catches it.
func TestDecodeNodeInfo_GroundTruth(t *testing.T) {
	payload := []byte{
		0x0a, 0x09, '!', '1', '1', '2', '2', '3', '3', '4', '4', // 1 id
		0x12, 0x05, 'a', 'l', 'p', 'h', 'a', // 2 long_name
		0x1a, 0x02, 'A', 'L', // 3 short_name
		0x28, 0x2b, // 5 hw_model = 43
		0x38, 0x00, // 7 role = 0 (CLIENT)
		0x42, 0x03, 0xaa, 0xbb, 0xcc, // 8 public_key (3 bytes)
	}
	res := &Result{}
	if err := decodeNodeInfo(res, payload); err != nil {
		t.Fatalf("decodeNodeInfo: %v", err)
	}
	ni := res.NodeInfo
	if ni == nil {
		t.Fatal("NodeInfo not populated")
	}
	if ni.ID != "!11223344" {
		t.Errorf("ID = %q, want !11223344 (field 1)", ni.ID)
	}
	if ni.LongName != "alpha" {
		t.Errorf("LongName = %q, want alpha (field 2, not 3)", ni.LongName)
	}
	if ni.ShortName != "AL" {
		t.Errorf("ShortName = %q, want AL (field 3, not 2)", ni.ShortName)
	}
	if !ni.HasHWModel || ni.HWModel != 43 {
		t.Errorf("HWModel = %d (has=%v), want 43 (field 5)", ni.HWModel, ni.HasHWModel)
	}
	// role = 0 is a real value (CLIENT), which is exactly why HasRole
	// exists: protobuf does not transmit a zero, so an explicit 0 and an
	// absent field look identical without it.
	if !ni.HasRole || ni.Role != 0 {
		t.Errorf("Role = %d (has=%v), want 0/true (field 7 present with value 0)", ni.Role, ni.HasRole)
	}
	if !ni.HasPublicKey {
		t.Errorf("HasPublicKey = false, want true (field 8 present)")
	}
	if ni.IsLicensed || ni.IsUnmessagable {
		t.Errorf("is_licensed/is_unmessagable = %v/%v, want false/false (absent)", ni.IsLicensed, ni.IsUnmessagable)
	}
}

// TestDecodeTelemetry_DeviceMetrics pins the nesting (Telemetry field 2 is
// an embedded DeviceMetrics message) and the three floats inside it.
func TestDecodeTelemetry_DeviceMetrics(t *testing.T) {
	device := []byte{
		0x08, 0x5b, // 1 battery_level = 91
		0x15, 0x9a, 0x99, 0x89, 0x40, // 2 voltage = 4.3 (float)
		0x1d, 0x00, 0x00, 0x20, 0x41, // 3 channel_utilization = 10.0
		0x25, 0xcd, 0xcc, 0x4c, 0x3e, // 4 air_util_tx = 0.2
		0x28, 0xc0, 0xd4, 0x01, // 5 uptime_seconds = 27200 (0x40 | 0x54<<7 | 1<<14)
	}
	payload := append([]byte{
		0x0d, 0x40, 0xe2, 0x01, 0x00, // 1 time (fixed32) = 123456
		0x12, byte(len(device)), // 2 device_metrics, embedded message
	}, device...)
	// 6 local_stats present but not interpreted.
	payload = append(payload, 0x32, 0x02, 0x08, 0x01)

	res := &Result{}
	if err := decodeTelemetry(res, payload); err != nil {
		t.Fatalf("decodeTelemetry: %v", err)
	}
	tm := res.Telemetry
	if tm == nil || tm.Device == nil {
		t.Fatal("Telemetry/DeviceMetrics not populated")
	}
	if !tm.HasTime || tm.Time != 123456 {
		t.Errorf("Time = %d (has=%v), want 123456 (field 1, fixed32)", tm.Time, tm.HasTime)
	}
	d := tm.Device
	if !d.HasBatteryLevel || d.BatteryLevel != 91 {
		t.Errorf("BatteryLevel = %d, want 91", d.BatteryLevel)
	}
	if !d.HasVoltage || !approx(d.Voltage, 4.3) {
		t.Errorf("Voltage = %v, want ~4.3 (float, not varint)", d.Voltage)
	}
	if !d.HasChannelUtilization || !approx(d.ChannelUtilization, 10.0) {
		t.Errorf("ChannelUtilization = %v, want 10.0", d.ChannelUtilization)
	}
	if !d.HasAirUtilTx || !approx(d.AirUtilTx, 0.2) {
		t.Errorf("AirUtilTx = %v, want ~0.2", d.AirUtilTx)
	}
	if !d.HasUptimeSeconds || d.UptimeSeconds != 27200 {
		t.Errorf("UptimeSeconds = %d, want 27200", d.UptimeSeconds)
	}
	// A metric group this decoder does not interpret must still be visible
	// as present, rather than vanishing.
	if len(tm.OtherVariants) != 1 || tm.OtherVariants[0] != "local_stats" {
		t.Errorf("OtherVariants = %v, want [local_stats]", tm.OtherVariants)
	}
}

// TestDecodeRouting_ErrorReasonZeroIsAnAck records the semantics that make
// this portnum easy to misread: error_reason = 0 (NONE) is an
// acknowledgement, so its presence matters and must not be dropped as an
// empty value.
func TestDecodeRouting_ErrorReasonZeroIsAnAck(t *testing.T) {
	res := &Result{}
	if err := decodeRouting(res, []byte{0x18, 0x00}); err != nil { // 3 error_reason = 0
		t.Fatalf("decodeRouting: %v", err)
	}
	if res.Routing == nil || !res.Routing.HasErrorReason || res.Routing.ErrorReason != 0 {
		t.Fatalf("Routing = %+v, want error_reason 0 recorded as present", res.Routing)
	}

	res = &Result{}
	if err := decodeRouting(res, []byte{0x18, 0x05}); err != nil { // NO_RESPONSE etc.
		t.Fatalf("decodeRouting: %v", err)
	}
	if res.Routing.ErrorReason != 5 {
		t.Errorf("ErrorReason = %d, want 5", res.Routing.ErrorReason)
	}

	res = &Result{}
	if err := decodeRouting(res, []byte{0x0a, 0x00}); err != nil { // 1 route_request
		t.Fatalf("decodeRouting: %v", err)
	}
	if !res.Routing.HasRouteRequest || res.Routing.HasErrorReason {
		t.Errorf("Routing = %+v, want route_request present and no error_reason", res.Routing)
	}
}

// TestDecodedFields_OmitsWhatThePacketDidNotState is the storage contract:
// an absent key means "not stated", so no consumer can mistake a default
// for a measurement.
func TestDecodedFields_OmitsWhatThePacketDidNotState(t *testing.T) {
	res := &Result{Portnum: PortNumPosition, Position: &Position{}}
	f, ok := res.DecodedFields()
	if !ok {
		t.Fatal("DecodedFields returned ok=false for a decoded position")
	}
	if _, present := f["latitude_i"]; present {
		t.Errorf("latitude_i present for a no-fix position: %+v", f)
	}
	if got, want := f["has_fix"], false; got != want {
		t.Errorf("has_fix = %v, want %v", got, want)
	}

	res = &Result{Portnum: PortNumTelemetry, Telemetry: &Telemetry{Device: &DeviceMetrics{
		HasBatteryLevel: true, BatteryLevel: 91,
	}}}
	f, _ = res.DecodedFields()
	dev, isMap := f["device_metrics"].(map[string]any)
	if !isMap {
		t.Fatalf("device_metrics missing or wrong type: %+v", f)
	}
	if dev["battery_level"] != uint32(91) {
		t.Errorf("battery_level = %v, want 91", dev["battery_level"])
	}
	if _, present := dev["voltage"]; present {
		t.Errorf("voltage present though the packet never stated it: %+v", dev)
	}
}

// TestDecodedFields_UnhandledPortnumStoresNothing keeps the raw-frame-first
// rule visible: an uninterpreted payload writes no decoded row, and its
// bytes stay in raw_frames.
func TestDecodedFields_UnhandledPortnumStoresNothing(t *testing.T) {
	res := &Result{Portnum: PortNum(99), RawPayload: []byte{1, 2, 3}}
	if f, ok := res.DecodedFields(); ok {
		t.Errorf("DecodedFields ok=true for an uninterpreted portnum: %+v", f)
	}
}

func TestPortNumName(t *testing.T) {
	for _, tc := range []struct {
		p    PortNum
		want string
	}{
		{PortNumTextMessage, "TEXT_MESSAGE_APP"},
		{PortNumRouting, "ROUTING_APP"},
		{PortNumTelemetry, "TELEMETRY_APP"},
		{PortNum(99), "PORTNUM_99"},
	} {
		if got := tc.p.Name(); got != tc.want {
			t.Errorf("PortNum(%d).Name() = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func approx(got, want float32) bool {
	d := got - want
	if d < 0 {
		d = -d
	}
	return d < 0.0001
}
