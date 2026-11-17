package diag

import (
	"testing"
	"time"
)

func latencyFixture(rtt float64) Measurement {
	start := time.Now().UTC()
	m := Measurement{Kind: "udp_rtt", Target: "fixture", Status: "ok", Started: start}
	for i := 0; i < 200; i++ {
		value := rtt
		if i < 50 {
			value = 999
		}
		m.Samples = append(m.Samples, Sample{Sequence: i, At: start.Add(time.Duration(i) * 100 * time.Millisecond), OK: true, RTT: value})
	}
	s := Summarize(m.Samples)
	m.Stats = &s
	return m
}

func TestLoadedLatencyExcludesWarmupAndRequiresCompleteLoad(t *testing.T) {
	a := latencyFixture(10)
	b := latencyFixture(80)
	load := Measurement{Status: "ok", Data: map[string]any{"full_interval": true}}
	m := LoadedLatency(a, b, load, "download")
	if m.Status != "ok" || m.Data["p95_increase_ms"] != float64(70) {
		t.Fatalf("incorrect result: %+v", m)
	}
	load.Status = "limited"
	if m := LoadedLatency(a, b, load, "download"); m.Status != "unavailable" {
		t.Fatal("incomplete load accepted")
	}
	b.Target = "different"
	load.Status = "ok"
	if m := LoadedLatency(a, b, load, "download"); m.Status != "unavailable" {
		t.Fatal("different destinations compared")
	}
}

func TestMissingRouteMetadataDoesNotImplyNetworkChange(t *testing.T) {
	a := Environment{LinkFingerprint: "same", RouteAvailable: true, ActiveInterface: "test", Gateway: "192.0.2.1"}
	b := Environment{LinkFingerprint: "same"}
	if !SameNetwork(a, b) {
		t.Fatal("missing metadata treated as observed change")
	}
	b.LinkFingerprint = "changed"
	if SameNetwork(a, b) {
		t.Fatal("interface change ignored")
	}
}

func TestPacketSizeDoesNotInventExactPMTU(t *testing.T) {
	m := Measurement{Kind: "packet_size", Status: "ok", Data: map[string]any{"packet_bytes": 1200, "fragmentation": "disabled"}, Stats: &Statistics{Sent: 15, Received: 15}}
	assessment := PacketSizeAssessment([]Measurement{m}, "fixture")
	if assessment.Status != "ok" || assessment.Data["exact_pmtu_known"] != false || assessment.Data["largest_confirmed_udp_payload_bytes"] != 1200 {
		t.Fatal(assessment)
	}
	m.Status = "limited"
	if assessment := PacketSizeAssessment([]Measurement{m}, "fixture"); assessment.Status != "unavailable" {
		t.Fatal("quota-limited measurement used as MTU evidence")
	}
}

func stableLatency(rtt float64) Measurement {
	start := time.Now().UTC()
	m := Measurement{Kind: "udp_rtt", Target: "fixture", Status: "ok", Started: start}
	for i := 0; i < 200; i++ {
		m.Samples = append(m.Samples, Sample{Sequence: i, At: start.Add(time.Duration(i) * 100 * time.Millisecond), OK: true, RTT: rtt})
	}
	return m
}

func TestRecoveryPreventsAttributingPersistentDelayToLoad(t *testing.T) {
	idle := stableLatency(10)
	loaded := stableLatency(100)
	load := Measurement{Status: "ok", Data: map[string]any{"full_interval": true}}
	m := LoadedLatency(idle, loaded, load, "download")
	AssessRecovery(&m, idle, stableLatency(90))
	if m.Status != "inconclusive" || m.Reason != "latency_did_not_recover" {
		t.Fatal(m)
	}
	m = LoadedLatency(idle, loaded, load, "download")
	AssessRecovery(&m, idle, stableLatency(12))
	if m.Status != "ok" {
		t.Fatal(m)
	}
}

func TestRateTrialRequiresBothUnlimitedControls(t *testing.T) {
	idle := stableLatency(10)
	loads := []Measurement{{Status: "ok", Data: map[string]any{"full_interval": true}}, {Status: "ok", Data: map[string]any{"full_interval": true}}, {Status: "ok", Data: map[string]any{"full_interval": true}}}
	delays := []Measurement{stableLatency(100), stableLatency(50), stableLatency(110)}
	recoveries := []Measurement{stableLatency(10), stableLatency(10), stableLatency(10)}
	m := RateTrialAssessment("download", idle, loads, delays, recoveries, 1000)
	if m.Status != "ok" {
		t.Fatal(m)
	}
	delays[2] = stableLatency(40)
	m = RateTrialAssessment("download", idle, loads, delays, recoveries, 1000)
	if m.Status == "ok" {
		t.Fatal("natural improvement accepted as a workaround", m)
	}
}

func TestNetworkMonitorTracksDNSAndProxyChanges(t *testing.T) {
	a := Environment{DNSFingerprint: "a", ProxyStateKnown: true}
	b := Environment{DNSFingerprint: "b", ProxyStateKnown: true}
	if SameNetwork(a, b) {
		t.Fatal("DNS change ignored")
	}
	b.DNSFingerprint = "a"
	b.ProxyHint = true
	if SameNetwork(a, b) {
		t.Fatal("proxy change ignored")
	}
}

func TestPacketSizeRequiresRepeatedFailuresAndIgnoresLocalSendErrors(t *testing.T) {
	good := Measurement{Kind: "packet_size", Status: "ok", Data: map[string]any{"packet_bytes": 1200, "fragmentation": "disabled"}, Stats: &Statistics{Sent: 11, Received: 11}}
	bad := Measurement{Kind: "packet_size", Status: "failed", Data: map[string]any{"packet_bytes": 1400, "fragmentation": "disabled"}, Stats: &Statistics{Sent: 11, Lost: 11}}
	if m := PacketSizeAssessment([]Measurement{good, bad}, "fixture"); m.Data["large_packets_failed"] == true {
		t.Fatal("single failed interval accepted", m)
	}
	if m := PacketSizeAssessment([]Measurement{good, bad, bad}, "fixture"); m.Data["large_packets_failed"] != true {
		t.Fatal(m)
	}
	bad.Stats = &Statistics{Sent: 0, LocalErrors: 11}
	if m := PacketSizeAssessment([]Measurement{good, bad, bad}, "fixture"); m.Data["large_packets_failed"] == true {
		t.Fatal("local send errors misclassified", m)
	}
}

func TestFullReportRetainsLinksBetweenMeasurements(t *testing.T) {
	section := Report{Command: "speed", Measurements: []Measurement{
		{ID: "source", Kind: "udp_rtt"},
		{ID: "assessment", Kind: "bufferbloat", Data: map[string]any{"idle_measurement_id": "source", "evidence_measurements": []string{"source"}}},
	}}
	var result Report
	appendFullSection(&result, section)
	source := result.Measurements[0].ID
	report := result.Measurements[1]
	if report.Data["idle_measurement_id"] != source || report.Data["evidence_measurements"].([]string)[0] != source {
		t.Fatalf("invalid evidence references: %+v", report)
	}
}
