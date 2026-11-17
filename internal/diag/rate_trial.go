package diag

import (
	"context"
	"netdiag/internal/node"
	"time"
)

func runRateTrial(ctx context.Context, c, control *node.Client, phase string, rate int64, total *Budget, limit int64, gateway string) []Measurement {
	trial := Measurement{ID: "rate-trial-" + phase, Kind: "rate_limit_trial", Target: c.Base, Status: "unavailable", Reason: "traffic_budget", Data: map[string]any{"phase": phase, "rate_bytes_sec": rate, "design": "A-B-A", "duration_ms": 10000, "warmup_ms": 3000, "system_unchanged": true}}
	needed := int64(float64(rate) / 0.7 * 27 * 1.1)
	trial.Data["estimated_required_bytes"] = needed
	if limit < needed || ctx.Err() != nil {
		return []Measurement{trial}
	}
	reserved := total.Take(int(limit))
	local := NewBudget(int64(reserved))
	defer func() { total.Refund(reserved - int(local.Used.Load())) }()
	var values []Measurement
	baseline := QualityUDP(ctx, control, 10*time.Second, 128)
	baseline.ID = "trial-idle-" + phase
	values = append(values, baseline)
	var loads, delays, recoveries []Measurement
	for i, stage := range []string{"a1", "b", "a2"} {
		stageRate := int64(0)
		if stage == "b" {
			stageRate = rate
		}
		load, delay, localGateway := pairedLoad(ctx, c, control, phase, 10*time.Second, local, local.Left.Load()/int64(3-i), stageRate, gateway)
		localGateway.ID = "trial-gateway-" + phase + "-" + stage
		load.ID = "trial-load-" + phase + "-" + stage
		delay.ID = "trial-rtt-" + phase + "-" + stage
		recovery := QualityUDP(ctx, control, 10*time.Second, 128)
		recovery.ID = "trial-recovery-" + phase + "-" + stage
		loads = append(loads, load)
		delays = append(delays, delay)
		recoveries = append(recoveries, recovery)
		values = append(values, load, delay, localGateway, recovery)
	}
	trial = RateTrialAssessment(phase, baseline, loads, delays, recoveries, rate)
	return append(values, trial)
}

func RateTrialAssessment(phase string, idle Measurement, loads, delays, recoveries []Measurement, rate int64) Measurement {
	trial := Measurement{ID: "rate-trial-" + phase, Kind: "rate_limit_trial", Target: idle.Target, Status: "inconclusive", Reason: "incomplete_or_inconsistent_trials", Data: map[string]any{"phase": phase, "rate_bytes_sec": rate, "design": "A-B-A", "duration_ms": 10000, "warmup_ms": 3000, "system_unchanged": true}}
	if len(loads) != 3 || len(delays) != 3 || len(recoveries) != 3 || idle.Status != "ok" || idle.Kind != "udp_rtt" {
		return trial
	}
	base := SteadyStats(idle, 3*time.Second)
	if base.Received < 50 {
		return trial
	}
	stats := make([]Statistics, 3)
	for i := 0; i < 3; i++ {
		stats[i] = SteadyStats(delays[i], 3*time.Second)
		recovery := SteadyStats(recoveries[i], 3*time.Second)
		if loads[i].Status != "ok" || loads[i].Data["full_interval"] != true || delays[i].Status != "ok" || delays[i].Kind != "udp_rtt" || delays[i].Target != idle.Target || stats[i].Received < 50 || recoveries[i].Status != "ok" || recoveries[i].Kind != "udp_rtt" || recoveries[i].Target != idle.Target || recovery.Received < 50 || recovery.P95 > base.P95+max(10, base.P95*0.25) {
			return trial
		}
	}
	trial.Data["unlimited_before_p95_ms"] = stats[0].P95
	trial.Data["limited_p95_ms"] = stats[1].P95
	trial.Data["unlimited_after_p95_ms"] = stats[2].P95
	trial.Data["limited_loss_percent"] = stats[1].LossPercent
	trial.Data["evidence_measurements"] = []string{delays[0].ID, delays[1].ID, delays[2].ID}
	if stats[0].P95-base.P95 >= 20 && stats[2].P95-base.P95 >= 20 && stats[1].P95 < min(stats[0].P95, stats[2].P95)*0.8 && stats[1].LossPercent <= min(stats[0].LossPercent, stats[2].LossPercent) {
		trial.Status = "ok"
		trial.Reason = ""
	} else {
		trial.Reason = "improvement_not_reproduced"
	}
	return trial
}
