package diag

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestStatisticsDoNotBridgeLoss(t *testing.T) {
	s := Summarize([]Sample{{Sequence: 0, OK: true, RTT: 10}, {Sequence: 1, OK: true, RTT: 14}, {Sequence: 2}, {Sequence: 3}, {Sequence: 4, OK: true, RTT: 100}, {Sequence: 5, OK: true, RTT: 110}})
	if s.Jitter != 7 || s.JitterPairs != 2 || s.LongestLoss != 2 || s.Lost != 2 || s.Sent != 6 || math.Abs(s.LossPercent-100.0/3) > 0.001 {
		t.Fatalf("unexpected statistics: %+v", s)
	}
	if s.P99 != nil {
		t.Fatal("p99 on a small sample")
	}
}

func TestMissingLatencyIsNullInJSON(t *testing.T) {
	value, err := json.Marshal(Summarize([]Sample{{Sequence: 0}}))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"min_ms":null`, `"median_ms":null`, `"adjacent_rtt_jitter_ms":null`} {
		if !strings.Contains(string(value), key) {
			t.Fatalf("%s: %s", key, value)
		}
	}
	value, _ = json.Marshal(Sample{Sequence: 1})
	if !strings.Contains(string(value), `"rtt_ms":null`) {
		t.Fatal(string(value))
	}
}

func TestQuantilesAndEmptySamples(t *testing.T) {
	var samples []Sample
	for i := 1; i <= 100; i++ {
		samples = append(samples, Sample{Sequence: i, OK: true, RTT: float64(i)})
	}
	s := Summarize(samples)
	if s.Median != 50 || s.P95 != 95 || s.P99 == nil || *s.P99 != 99 {
		t.Fatalf("unexpected quantiles: %+v", s)
	}
	if e := Summarize(nil); e.Sent != 0 || e.LossPercent != 0 {
		t.Fatal(e)
	}
}

func TestTargetNormalizationRemovesSecrets(t *testing.T) {
	target, err := NormalizeTarget("https://name:password@example.org/private?token=secret#fragment")
	if err != nil || target.URL != "https://example.org/" || target.Name != "example.org" {
		t.Fatalf("%+v %v", target, err)
	}
	for _, value := range []string{"file:///etc/passwd", "ftp://example.org", "https://", "https://bad host/"} {
		if _, err := NormalizeTarget(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestIPv6TargetAndPortValidation(t *testing.T) {
	for _, raw := range []string{"https://[2001:db8::1]:8443/", "http://[::1]/"} {
		v, err := NormalizeTarget(raw)
		if err != nil || v.URL != raw {
			t.Fatalf("%s: %+v %v", raw, v, err)
		}
	}
	for _, raw := range []string{"https://example.org:0/", "https://example.org:65536/"} {
		if _, err := NormalizeTarget(raw); err == nil {
			t.Fatal("invalid port accepted", raw)
		}
	}
}

func TestSendFailuresAreNotNetworkLoss(t *testing.T) {
	late := 900.0
	s := Summarize([]Sample{{Sequence: 0, SendError: true}, {Sequence: 1, OK: true, RTT: 10}, {Sequence: 2, Late: true, LateRTT: &late}})
	if s.Attempts != 3 || s.Sent != 2 || s.LocalErrors != 1 || s.Lost != 1 || s.LateReplies != 1 || s.LossPercent != 50 {
		t.Fatal(s)
	}
}
