package diag

import (
	"context"
	"math"
	"netdiag/internal/node"
	"sync"
	"time"
)

func loadWithinBudget(ctx context.Context, c *node.Client, phase string, streams int, duration time.Duration, total *Budget, limit int64, rate int64) Measurement {
	reserved := total.Take(int(max(0, limit)))
	local := NewBudget(int64(reserved))
	defer func() { total.Refund(reserved - int(local.Used.Load())) }()
	m := NodeLoad(ctx, c, phase, streams, duration, local, rate)
	m.Data["phase_budget_bytes"] = reserved
	return m
}

func pairedLoad(ctx context.Context, c, control *node.Client, phase string, duration time.Duration, budget *Budget, limit, rate int64, gateway string) (Measurement, Measurement, Measurement) {
	var load Measurement
	local := Measurement{Kind: "icmp_rtt", Target: "local-gateway", Status: "unavailable", Reason: "physical_gateway_unavailable"}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); load = loadWithinBudget(ctx, c, phase, 2, duration, budget, limit, rate) }()
	if gateway != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local = QualityICMP(ctx, gateway, duration)
			local.Target = "local-gateway"
			delete(local.Data, "target_ip")
		}()
	}
	latency := QualityUDP(ctx, control, duration, 128)
	wg.Wait()
	return load, latency, local
}

func speedBudgetAssessment(singles map[string]Measurement, available int64) Measurement {
	m := Measurement{ID: "speed-plan", Kind: "speed_plan", Status: "unavailable", Reason: "insufficient_calibration", Data: map[string]any{"available_mib": float64(available) / (1 << 20), "estimate_only": true}}
	down := number(singles["download"].Data["download_mbps"]) * 1e6 / 8
	up := number(singles["upload"].Data["upload_mbps"]) * 1e6 / 8
	if down <= 0 || up <= 0 {
		return m
	}
	required := (down + up) * 50 * 1.15
	m.Data["estimated_full_test_mib"] = math.Ceil(required / (1 << 20))
	m.Data["estimate_scope"] = "single-stream and three primary load phases; optional repeated solution trials use remaining data"
	m.Status = "ok"
	m.Reason = ""
	if required > float64(available) {
		m.Status = "inconclusive"
		m.Reason = "insufficient_budget_for_observed_rate"
	}
	return m
}
