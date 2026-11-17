package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netdiag/internal/diag"
)

func TestHelpAndNoninteractiveRequirements(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{{[]string{"--help"}, 0}, {[]string{"--version"}, 0}, {[]string{"check"}, 2}, {[]string{"speed", "--mode", "direct"}, 2}, {[]string{"check", "--mode", "bad"}, 2}, {[]string{"check", "--mode", "direct", "--only-target"}, 2}} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), tc.args, strings.NewReader(""), &out, &errOut, false)
		if code != tc.code {
			t.Fatalf("%v => %d (%s)", tc.args, code, errOut.String())
		}
	}
}

func TestReportRoundTripAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	r := diag.Report{Schema: diag.Schema, Version: diag.Version, Started: time.Now(), Mode: "direct", Measurements: []diag.Measurement{{Kind: "http_baseline", Target: "https://example.org/", Status: "ok"}}}
	if err := WriteReport(path, r); err != nil {
		t.Fatal(err)
	}
	saved, err := ReadReport(path)
	if err != nil || saved.Mode != "direct" {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if WriteReport(path, diag.Report{}) == nil {
		t.Fatal("overwrote report")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("report changed")
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"report", "--input", path, "--format", "json"}, strings.NewReader(""), &out, &errOut, false)
	if code != 0 || !strings.Contains(out.String(), `"schema_version": 1`) {
		t.Fatalf("%d %s %s", code, out.String(), errOut.String())
	}
}

func TestComparisonUsesMeasurements(t *testing.T) {
	before := diag.Report{Mode: "direct", Measurements: []diag.Measurement{{ID: "a", Kind: "http_baseline", Target: "https://example.org/", Status: "failed"}}}
	after := diag.Report{Mode: "vpn", Measurements: []diag.Measurement{{ID: "b", Kind: "http_baseline", Target: "https://example.org/", Status: "ok"}}}
	Compare(before, &after)
	if len(after.Measurements) != 2 || after.Measurements[1].Data["before"] != "failed" || after.Measurements[1].Data["after"] != "ok" || after.Measurements[1].Data["vpn_routing_proven"] != false {
		t.Fatal(after.Measurements)
	}
}

func TestQualityWithoutRepliesDoesNotExitSuccessfully(t *testing.T) {
	for _, status := range []string{"failed", "unavailable"} {
		r := diag.Report{Command: "quality", Mode: "direct", Measurements: []diag.Measurement{{Kind: "udp_rtt", Status: status, Reason: "no_udp_replies"}}}
		r.Findings = diag.Analyze(r)
		var out, errOut bytes.Buffer
		if code := emit(&out, &errOut, r, "text", "", false); code == 0 {
			t.Fatal("empty quality test accepted", out.String())
		}
	}
}

func TestReportShowsBufferbloatAndSanitizesEveryField(t *testing.T) {
	r := diag.Report{Command: "speed", Mode: "direct\x1b]52;c;dGVzdA==\a", Measurements: []diag.Measurement{{Kind: "bufferbloat", Status: "ok", Data: map[string]any{"phase": "download\x1b[31m", "idle_p95_ms": 10.0, "loaded_p95_ms": 27.125, "p95_increase_ms": 17.125}}, {Kind: "comparison", Data: map[string]any{"before": "ok\x1b[31m", "after": "failed"}}, {Kind: "throughput", Data: map[string]any{"phase": "upload\x1b[31m"}}}}
	var out bytes.Buffer
	PrintReport(&out, r, false)
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("terminal escape emitted")
	}
	if !strings.Contains(out.String(), "17.12") && !strings.Contains(out.String(), "17.13") {
		t.Fatal("bufferbloat result hidden", out.String())
	}
}

func TestComparisonIncludesReasonsAndTiming(t *testing.T) {
	before := diag.Report{Measurements: []diag.Measurement{{ID: "a", Kind: "http_baseline", Target: "https://example.org/", Status: "failed", Reason: "timeout", Data: map[string]any{"first_byte_ms": 100.0}}}}
	after := diag.Report{Measurements: []diag.Measurement{{ID: "b", Kind: "http_baseline", Target: "https://example.org/", Status: "failed", Reason: "tls_hostname", Data: map[string]any{"first_byte_ms": 200.0}}}}
	Compare(before, &after)
	m := after.Measurements[1]
	if m.Status != "changed" || m.Data["after_reason"] != "tls_hostname" || m.Data["before_values"].(map[string]any)["first_byte_ms"] != 100.0 {
		t.Fatal(m)
	}
}
