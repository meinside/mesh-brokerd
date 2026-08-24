package decode

import "math"

// Telemetry is the decoded payload of a TELEMETRY_APP packet. Field
// numbers are from the schema (meshtastic/telemetry.proto), read rather
// than generated (ADR-13):
//
//	Telemetry:      1 time (fixed32), 2 device_metrics, 3 environment_metrics,
//	                4 air_quality_metrics, 5 power_metrics, 6 local_stats,
//	                7 health_metrics, 8 host_metrics, 9 traffic_management_stats
//	DeviceMetrics:  1 battery_level (uint32), 2 voltage (float),
//	                3 channel_utilization (float), 4 air_util_tx (float),
//	                5 uptime_seconds (uint32)
//
// Only DeviceMetrics is interpreted: it is the one variant these boards
// produce, and the one a monitoring view wants. The others are recorded by
// *name* in OtherVariants so a new kind of telemetry shows up as an
// explicit "present but not parsed" rather than as silence — the raw bytes
// are in raw_frames either way.
type Telemetry struct {
	Time    uint32
	HasTime bool

	Device *DeviceMetrics

	// OtherVariants lists field numbers present besides time and
	// device_metrics, in schema order.
	OtherVariants []string
}

// DeviceMetrics is Telemetry.device_metrics.
type DeviceMetrics struct {
	BatteryLevel    uint32
	HasBatteryLevel bool
	// Voltage is in volts; channel utilization and air-util-tx are
	// percentages, both floats on the wire (fixed32 bits, not varints).
	Voltage               float32
	HasVoltage            bool
	ChannelUtilization    float32
	HasChannelUtilization bool
	AirUtilTx             float32
	HasAirUtilTx          bool
	UptimeSeconds         uint32
	HasUptimeSeconds      bool
}

const (
	feTelemetryTime          = 1
	feTelemetryDeviceMetrics = 2

	feDeviceMetricsBatteryLevel       = 1
	feDeviceMetricsVoltage            = 2
	feDeviceMetricsChannelUtilization = 3
	feDeviceMetricsAirUtilTx          = 4
	feDeviceMetricsUptimeSeconds      = 5
)

// telemetryVariantNames maps the non-device_metrics variants to the names
// used in stored output, so an unparsed variant is still identifiable.
var telemetryVariantNames = map[int]string{
	3: "environment_metrics",
	4: "air_quality_metrics",
	5: "power_metrics",
	6: "local_stats",
	7: "health_metrics",
	8: "host_metrics",
	9: "traffic_management_stats",
}

// decodeTelemetry implements PortNumTelemetry.
func decodeTelemetry(res *Result, payload []byte) error {
	fields, err := parsePBFields(payload)
	if err != nil {
		return err
	}

	t := &Telemetry{}
	if f, ok := lastField(fields, feTelemetryTime); ok {
		t.Time = f.Fixed32
		t.HasTime = true
	}
	if f, ok := lastField(fields, feTelemetryDeviceMetrics); ok {
		dm, err := parseDeviceMetrics(f.Bytes)
		if err != nil {
			return err
		}
		t.Device = dm
	}
	// Deterministic order: iterate the schema's field numbers, not the map.
	for n := 3; n <= 9; n++ {
		if _, ok := lastField(fields, n); ok {
			t.OtherVariants = append(t.OtherVariants, telemetryVariantNames[n])
		}
	}
	res.Telemetry = t
	return nil
}

func parseDeviceMetrics(b []byte) (*DeviceMetrics, error) {
	fields, err := parsePBFields(b)
	if err != nil {
		return nil, err
	}
	dm := &DeviceMetrics{}
	if f, ok := lastField(fields, feDeviceMetricsBatteryLevel); ok {
		dm.BatteryLevel = uint32(f.Varint)
		dm.HasBatteryLevel = true
	}
	if f, ok := lastField(fields, feDeviceMetricsVoltage); ok {
		dm.Voltage = math.Float32frombits(f.Fixed32)
		dm.HasVoltage = true
	}
	if f, ok := lastField(fields, feDeviceMetricsChannelUtilization); ok {
		dm.ChannelUtilization = math.Float32frombits(f.Fixed32)
		dm.HasChannelUtilization = true
	}
	if f, ok := lastField(fields, feDeviceMetricsAirUtilTx); ok {
		dm.AirUtilTx = math.Float32frombits(f.Fixed32)
		dm.HasAirUtilTx = true
	}
	if f, ok := lastField(fields, feDeviceMetricsUptimeSeconds); ok {
		dm.UptimeSeconds = uint32(f.Varint)
		dm.HasUptimeSeconds = true
	}
	return dm, nil
}
