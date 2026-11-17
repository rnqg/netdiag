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
