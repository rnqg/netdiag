package diag

import (
	"math"
	"sort"
)

func Summarize(samples []Sample) Statistics {
	s := Statistics{Sent: len(samples)}
	values := make([]float64, 0, len(samples))
	burst := 0
	for i, p := range samples {
		if !p.OK {
			s.Lost++
			burst++
			if burst > s.LongestLoss {
				s.LongestLoss = burst
			}
			continue
		}
		burst = 0
		s.Received++
		values = append(values, p.RTT)
		if i > 0 && samples[i-1].OK && p.Sequence == samples[i-1].Sequence+1 {
			s.Jitter += math.Abs(p.RTT - samples[i-1].RTT)
			s.JitterPairs++
		}
	}
	if s.Sent > 0 {
		s.LossPercent = 100 * float64(s.Lost) / float64(s.Sent)
	}
	if s.JitterPairs > 0 {
		s.Jitter /= float64(s.JitterPairs)
	}
	if len(values) == 0 {
		return s
	}
	sort.Float64s(values)
	s.Min = values[0]
	s.Max = values[len(values)-1]
	s.Median = percentile(values, 0.5)
	s.P95 = percentile(values, 0.95)
	if len(values) >= 100 {
		v := percentile(values, 0.99)
		s.P99 = &v
	}
	return s
}

func percentile(values []float64, p float64) float64 {
	i := int(math.Ceil(float64(len(values))*p)) - 1
	if i < 0 {
		i = 0
	}
	return values[i]
}
