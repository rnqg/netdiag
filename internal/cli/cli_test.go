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
