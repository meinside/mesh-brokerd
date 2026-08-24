package decode

// DecodedFields returns what a portnum decoder understood, as a map ready
// to be stored as JSON (docs/storage-schema.md's decoded_payloads.fields).
// ok is false when this portnum has no interpreter, or when nothing was
// decoded at all — the caller stores no decoded_payloads row in that case,
// while raw_frames keeps the bytes regardless (ADR-3, ADR-15).
//
// One map rather than a table per portnum: a new portnum then costs a
// decoder and nothing else — no migration, no new table, no new column.
// Absent keys mean "the packet did not state this"; a key is present only
// when its Has* flag was set, so a stored 0 is always a real zero.
func (r *Result) DecodedFields() (fields map[string]any, ok bool) {
	switch {
	case r.TextMessage != nil:
		return map[string]any{"text": r.TextMessage.Text}, true

	case r.Position != nil:
		f := map[string]any{}
		if r.Position.HasLatLon {
			f["latitude_i"] = r.Position.LatitudeI
			f["longitude_i"] = r.Position.LongitudeI
		}
		if r.Position.HasPrecisionBits {
			f["precision_bits"] = r.Position.PrecisionBits
		}
		// A position with no fix is normal traffic, not a decode failure
		// (docs/outbound-relay.md §4.1) — record it as such rather than
		// storing an empty object with no explanation.
		f["has_fix"] = r.Position.HasLatLon
		return f, true

	case r.NodeInfo != nil:
		ni := r.NodeInfo
		f := map[string]any{}
		if ni.ID != "" {
			f["id"] = ni.ID
		}
		if ni.LongName != "" {
			f["long_name"] = ni.LongName
		}
		if ni.ShortName != "" {
			f["short_name"] = ni.ShortName
		}
		if ni.HasHWModel {
			f["hw_model"] = ni.HWModel
		}
		if ni.HasRole {
			f["role"] = ni.Role
		}
		f["is_licensed"] = ni.IsLicensed
		f["is_unmessagable"] = ni.IsUnmessagable
		f["has_public_key"] = ni.HasPublicKey
		return f, true

	case r.Telemetry != nil:
		t := r.Telemetry
		f := map[string]any{}
		if t.HasTime {
			f["time"] = t.Time
		}
		if t.Device != nil {
			d := map[string]any{}
			if t.Device.HasBatteryLevel {
				d["battery_level"] = t.Device.BatteryLevel
			}
			if t.Device.HasVoltage {
				d["voltage"] = t.Device.Voltage
			}
			if t.Device.HasChannelUtilization {
				d["channel_utilization"] = t.Device.ChannelUtilization
			}
			if t.Device.HasAirUtilTx {
				d["air_util_tx"] = t.Device.AirUtilTx
			}
			if t.Device.HasUptimeSeconds {
				d["uptime_seconds"] = t.Device.UptimeSeconds
			}
			f["device_metrics"] = d
		}
		if len(t.OtherVariants) > 0 {
			f["other_variants_present"] = t.OtherVariants
		}
		return f, true

	case r.Routing != nil:
		f := map[string]any{}
		if r.Routing.HasErrorReason {
			// 0 = NONE, which is an acknowledgement rather than an absence
			// of information (routing.go).
			f["error_reason"] = r.Routing.ErrorReason
		}
		if r.Routing.HasRouteRequest {
			f["route_request_present"] = true
		}
		if r.Routing.HasRouteReply {
			f["route_reply_present"] = true
		}
		return f, true
	}

	return nil, false
}
