package diag

import "time"

func SteadyStats(m Measurement, warmup time.Duration) Statistics {
	cut := m.Started.Add(warmup)
	values := []Sample{}
	for _, sample := range m.Samples {
		if !sample.At.Before(cut) {
			values = append(values, sample)
		}
	}
	return Summarize(values)
}

func LoadedLatency(idle, loaded, load Measurement, phase string) Measurement {
	m := Measurement{ID: "bufferbloat-" + phase, Kind: "bufferbloat", Target: loaded.Target, Status: "unavailable", Reason: "insufficient_rtt_or_load", Data: map[string]any{"phase": phase, "method": "udp_rtt", "saturation_proven": false, "warmup_ms": 5000, "idle_measurement_id": idle.ID, "loaded_measurement_id": loaded.ID, "load_measurement_id": load.ID}}
	a := SteadyStats(idle, 5*time.Second)
	b := SteadyStats(loaded, 5*time.Second)
	if idle.Status != "ok" || loaded.Status != "ok" || idle.Kind != "udp_rtt" || loaded.Kind != "udp_rtt" || idle.Target != loaded.Target || a.Received < 50 || b.Received < 50 || load.Status != "ok" || load.Data["full_interval"] != true {
		return m
	}
	m.Status = "ok"
	m.Reason = ""
	m.Data["idle_p95_ms"] = a.P95
	m.Data["loaded_p95_ms"] = b.P95
	m.Data["p95_increase_ms"] = b.P95 - a.P95
	m.Data["idle_loss_percent"] = a.LossPercent
	m.Data["loaded_loss_percent"] = b.LossPercent
	m.Data["interpretation"] = "Наблюдаемый рост RTT при созданной нагрузке; отсутствие роста не доказывает отсутствие очередей при иной нагрузке"
	return m
}

func PacketSizeAssessment(values []Measurement, peer string) Measurement {
	m := Measurement{ID: "packet-size-assessment", Kind: "path_mtu", Target: peer, Status: "unavailable", Reason: "no_fragmentation_control_or_successful_probes", Data: map[string]any{"exact_pmtu_known": false}}
	maxPayload := 0
	minFailed := 0
	for _, value := range values {
		if value.Kind != "packet_size" || value.Data["fragmentation"] != "disabled" || value.Stats == nil || value.Stats.Sent < 10 || value.Status == "partial" || value.Status == "limited" {
			continue
		}
		size := int(number(value.Data["packet_bytes"]))
		if value.Stats.Received >= 10 && size > maxPayload {
			maxPayload = size
		}
		if value.Stats.Received == 0 && (minFailed == 0 || size < minFailed) {
			minFailed = size
		}
	}
	if maxPayload == 0 {
		return m
	}
	m.Status = "ok"
	m.Reason = ""
	m.Data["largest_confirmed_udp_payload_bytes"] = maxPayload
	m.Data["large_packets_failed"] = minFailed > maxPayload
	m.Data["interpretation"] = "Подтверждён только проходящий размер. Потери более крупных проб не определяют точный PMTU и не устанавливают причину."
	return m
}
