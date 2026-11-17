package diag

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func RunCheck(ctx context.Context, opts Options) Report {
	r := NewReport("check", opts)
	limit := 60 * time.Second
	if opts.Profile == "deep" {
		limit = 180 * time.Second
	}
	run, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if opts.Profile == "deep" {
		r.Measurements = append(r.Measurements, WiFi(run, r.Environment.PhysicalInterface))
	}
	var mu sync.Mutex
	slots := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for index, target := range opts.Targets {
		wg.Add(1)
		go func(index int, target Target) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-run.Done():
				return
			}
			defer func() { <-slots }()
			if opts.Progress != nil {
				opts.Progress(target.Name)
			}
			values := checkTarget(run, target, opts.Profile)
			for i := range values {
				values[i].ID = fmt.Sprintf("target-%02d-%03d", index, i)
			}
			mu.Lock()
			r.Measurements = append(r.Measurements, values...)
			mu.Unlock()
		}(index, target)
	}
	wg.Wait()
	if opts.Profile == "deep" && run.Err() == nil && len(opts.Targets) > 0 {
		u, _ := url.Parse(opts.Targets[0].URL)
		if net.ParseIP(u.Hostname()) == nil {
			r.Measurements = append(r.Measurements, dnsMatrix(run, u.Hostname(), hasGlobalIPv6(r.Environment))...)
		}
	}
	sort.SliceStable(r.Measurements, func(i, j int) bool { return r.Measurements[i].ID < r.Measurements[j].ID })
	if opts.Traceroute && len(opts.Targets) > 0 {
		u, _ := url.Parse(opts.Targets[0].URL)
		r.Measurements = append(r.Measurements, Trace(run, u.Hostname()))
	}
	if len(r.Measurements) == 0 {
		r.Partial = true
	}
	if run.Err() == nil && len(opts.Targets) > 0 {
		u, _ := url.Parse(opts.Targets[0].URL)
		m := QualityICMP(run, u.Hostname(), 5*time.Second)
		m.ID = "short-icmp"
		r.Measurements = append(r.Measurements, m)
	}
	if run.Err() == nil && LocalGateway(r.Environment) != "" {
		m := QualityICMP(run, LocalGateway(r.Environment), 3*time.Second)
		m.ID = "short-gateway-icmp"
		m.Target = "local-gateway"
		delete(m.Data, "target_ip")
		r.Measurements = append(r.Measurements, m)
	}
	r.Finish(run.Err())
	return r
}

func RunFull(ctx context.Context, opts Options) Report {
	r := RunCheck(ctx, opts)
	r.Full = true
	if !r.NetworkChanged && ctx.Err() == nil {
		qualityOptions := opts
		qualityOptions.MaxBytes = min(opts.MaxBytes/8, 2<<20)
		if opts.Progress != nil {
			opts.Progress("Качество подключения и размеры пакетов")
		}
		quality := RunQuality(ctx, qualityOptions)
		appendFullSection(&r, quality)
		if !r.NetworkChanged && ctx.Err() == nil {
			speedOptions := opts
			speedOptions.MaxBytes -= qualityOptions.MaxBytes
			appendFullSection(&r, RunNodeSpeed(ctx, speedOptions))
		}
	}
	complete := 0
	for _, m := range r.Measurements {
		if m.Kind == "bufferbloat" && m.Status == "ok" {
			complete++
		}
	}
	r.Partial = r.Partial || complete < 3
	r.Finish(ctx.Err())
	return r
}

func appendFullSection(r *Report, section Report) {
	prefix := section.Command + "/"
	for _, m := range section.Measurements {
		m.ID = prefix + m.ID
		for _, key := range []string{"idle_measurement_id", "loaded_measurement_id", "load_measurement_id", "recovery_measurement_id"} {
			if id, ok := m.Data[key].(string); ok && id != "" {
				m.Data[key] = prefix + id
			}
		}
		if ids, ok := m.Data["evidence_measurements"].([]string); ok {
			updated := make([]string, len(ids))
			for i, id := range ids {
				updated[i] = prefix + id
			}
			m.Data["evidence_measurements"] = updated
		}
		r.Measurements = append(r.Measurements, m)
	}
	r.NetworkChanged = r.NetworkChanged || section.NetworkChanged || !SameNetwork(r.Environment, section.Environment)
	r.Partial = r.Partial || section.Partial
}

func checkTarget(ctx context.Context, target Target, profile string) []Measurement {
	u, _ := url.Parse(target.URL)
	result := []Measurement{Resolve(ctx, u.Hostname())}
	base := Probe(ctx, target, ProbeConfig{Protocol: "auto"})
	base.Kind = "http_baseline"
	result = append(result, base)
	if profile != "deep" || ctx.Err() != nil {
		return result
	}
	for i := 0; i < 2 && ctx.Err() == nil; i++ {
		m := Probe(ctx, target, ProbeConfig{Protocol: "auto"})
		m.Kind = "http_repeat"
		result = append(result, m)
	}
	addresses := measurementIPs(result[0])
	for _, family := range []string{"ipv4", "ipv6"} {
		has := false
		for _, ip := range addresses {
			if family == "ipv4" && ip.To4() != nil || family == "ipv6" && ip.To4() == nil {
				has = true
			}
		}
		if !has {
			result = append(result, Measurement{Kind: "ip_family", Target: target.URL, Status: "unavailable", Reason: "no_dns_address_for_family", Data: map[string]any{"family": family}})
			continue
		}
		if ctx.Err() != nil {
			break
		}
		m := Probe(ctx, target, ProbeConfig{Family: family, Protocol: "auto", Addresses: addresses})
		m.Kind = "ip_family"
		result = append(result, m)
	}
	pinned := []net.IP{}
	if peer, ok := base.Data["peer_ip"].(string); ok {
		if ip := net.ParseIP(peer); ip != nil {
			pinned = append(pinned, ip)
		}
	}
	if len(pinned) > 0 && u.Scheme == "https" {
		for _, protocol := range []string{"h1", "h2"} {
			if ctx.Err() != nil {
				break
			}
			m := Probe(ctx, target, ProbeConfig{Protocol: protocol, Addresses: pinned})
			m.Kind = "protocol"
			result = append(result, m)
		}
		if h3, ok := base.Data["alt_svc_h3"].(bool); ok && h3 && ctx.Err() == nil {
			port, _ := base.Data["alt_svc_h3_port"].(string)
			m := Probe(ctx, target, ProbeConfig{Protocol: "h3", Addresses: pinned, QUICPort: port})
			m.Kind = "protocol"
			result = append(result, m)
		}
		for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			if ctx.Err() != nil {
				break
			}
			m := Probe(ctx, target, ProbeConfig{Protocol: "h1", Addresses: pinned, TLSVersion: v})
			m.Kind = "tls_version"
			m.Data["requested_tls"] = tls.VersionName(v)
			result = append(result, m)
		}
	}
	if ctx.Err() == nil {
		result = append(result, transportTrials(ctx, target, result, pinned)...)
	}
	if base.Status == "failed" && ctx.Err() == nil && net.ParseIP(u.Hostname()) == nil {
		for _, method := range []string{"udp", "tcp", "doh", "dot"} {
			for _, resolver := range Resolvers {
				if ctx.Err() != nil {
					return result
				}
				trial := testDNSAlternative(ctx, target, u.Hostname(), resolver, method)
				result = append(result, trial...)
				if len(trial) > 0 && trial[len(trial)-1].Status == "ok" {
					return result
				}
			}
		}
	}
	return result
}

func dnsMatrix(ctx context.Context, host string, ipv6 bool) []Measurement {
	type task struct {
		resolver Resolver
		method   string
		qtype    uint16
	}
	tasks := []task{}
	for _, resolver := range Resolvers {
		addresses := []Resolver{resolver}
		if ipv6 && resolver.IPv6 != "" {
			copy := resolver
			copy.IP = resolver.IPv6
			addresses = append(addresses, copy)
		}
		for _, resolver := range addresses {
			for _, method := range []string{"udp", "tcp", "doh", "dot"} {
				for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
					tasks = append(tasks, task{resolver, method, qtype})
				}
				tasks = append(tasks, task{resolver, method, 0})
			}
		}
	}
	results := make([][]Measurement, len(tasks))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 6)
	for i, job := range tasks {
		wg.Add(1)
		go func(i int, job task) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				results[i] = []Measurement{{ID: fmt.Sprintf("dns-matrix-%02d-1", i), Kind: "dns_alternative", Target: host, Status: "unavailable", Reason: "deadline", Data: map[string]any{"resolver": job.resolver.Name, "resolver_ip": job.resolver.IP, "method": job.method}}}
				return
			}
			defer func() { <-slots }()
			queryHost := host
			qtype := job.qtype
			if qtype == 0 {
				queryHost = "netdiag-negative.invalid"
				qtype = dns.TypeA
			}
			count := 1
			if job.qtype == dns.TypeA {
				count = 2
			}
			for attempt := 1; attempt <= count && ctx.Err() == nil; attempt++ {
				m, _ := QueryDNS(ctx, queryHost, job.resolver, job.method, qtype)
				m.Data["attempt"] = attempt
				if job.qtype == 0 {
					m.Data["negative_control"] = true
					if m.Reason == "dns_NXDOMAIN" {
						m.Status = "ok"
						m.Reason = ""
						delete(m.Data, "failure_stage")
					} else if m.Status == "ok" || m.Reason == "dns_nodata" {
						m.Status = "failed"
						m.Reason = "dns_negative_control_unexpected"
						m.Data["failure_stage"] = "dns_response"
					}
				}
				m.ID = fmt.Sprintf("dns-matrix-%02d-%d", i, attempt)
				results[i] = append(results[i], m)
			}
		}(i, job)
	}
	wg.Wait()
	var measurements []Measurement
	for _, result := range results {
		measurements = append(measurements, result...)
	}
	return measurements
}

func transportTrials(ctx context.Context, target Target, measurements []Measurement, pinned []net.IP) []Measurement {
	var failed, working string
	var failedPort, workingPort string
	for _, m := range measurements {
		if m.Kind != "protocol" {
			continue
		}
		p, _ := m.Data["requested_protocol"].(string)
		if m.Status == "failed" {
			failed = p
			failedPort, _ = m.Data["requested_port"].(string)
		}
		if m.Status == "ok" && working == "" {
			working = p
			workingPort, _ = m.Data["requested_port"].(string)
		}
	}
	if failed == "" || working == "" || len(pinned) == 0 || failedPort != workingPort {
		return nil
	}
	values := []Measurement{}
	successes, failures := 0, 0
	for round := 0; round < 3 && ctx.Err() == nil; round++ {
		a := Probe(ctx, target, ProbeConfig{Protocol: failed, Addresses: pinned})
		a.Kind = "transport_trial_baseline"
		b := Probe(ctx, target, ProbeConfig{Protocol: working, Addresses: pinned})
		b.Kind = "transport_trial_candidate"
		values = append(values, a, b)
		if a.Status == "failed" {
			failures++
		}
		if b.Status == "ok" {
			successes++
		}
	}
	status := "inconclusive"
	if failures == 3 && successes == 3 {
		status = "ok"
	}
	return append(values, Measurement{Kind: "transport_solution", Target: target.URL, Status: status, Data: map[string]any{"failed_protocol": failed, "working_protocol": working, "candidate_successes": successes, "baseline_failures": failures, "rounds": 3, "same_ip": true, "system_unchanged": true}})
}

func testDNSAlternative(ctx context.Context, t Target, host string, r Resolver, method string) []Measurement {
	values := []Measurement{}
	passed, failed, dnsFailed := 0, 0, 0
	tcpFallback := false
	for round := 0; round < 3 && ctx.Err() == nil; round++ {
		query, ips := QueryDNS(ctx, host, r, method, dns.TypeA)
		query.Data["attempt"] = round + 1
		query.Data["solution_trial"] = true
		values = append(values, query)
		if query.Status != "ok" {
			break
		}
		tcpFallback = tcpFallback || query.Data["tcp_fallback"] == true
		base := Probe(ctx, t, ProbeConfig{Protocol: "auto"})
		base.Kind = "trial_baseline"
		values = append(values, base)
		alt := Probe(ctx, t, ProbeConfig{Protocol: "auto", Addresses: ips})
		alt.Kind = "trial_candidate"
		alt.Data["candidate"] = "dns"
		alt.Data["resolver_ip"] = r.IP
		alt.Data["resolver"] = r.Name
		alt.Data["dns_method"] = method
		values = append(values, alt)
		if base.Status == "failed" {
			failed++
		}
		if base.Reason == "dns_not_found" || base.Reason == "dns_timeout" || base.Reason == "dns_error" {
			dnsFailed++
		}
		if alt.Status == "ok" {
			passed++
		}
	}
	status := "inconclusive"
	if passed == 3 && failed == 3 {
		status = "ok"
	}
	m := Measurement{Kind: "solution_trial", Target: t.URL, Status: status, Started: time.Now().UTC(), Data: map[string]any{"candidate": "dns", "resolver_ip": r.IP, "resolver": r.Name, "dns_method": method, "candidate_successes": passed, "baseline_failures": failed, "baseline_dns_failures": dnsFailed, "rounds": 3, "system_unchanged": true, "tcp_fallback": tcpFallback, "automatic_eligible": status == "ok" && dnsFailed == 3 && method == "udp" && !tcpFallback}}
	return append(values, m)
}

func measurementIPs(m Measurement) []net.IP {
	result := []net.IP{}
	switch values := m.Data["addresses"].(type) {
	case []string:
		for _, value := range values {
			if ip := net.ParseIP(value); ip != nil {
				result = append(result, ip)
			}
		}
	case []any:
		for _, value := range values {
			if s, ok := value.(string); ok {
				if ip := net.ParseIP(s); ip != nil {
					result = append(result, ip)
				}
			}
		}
	}
	return result
}

func hasGlobalIPv6(e Environment) bool {
	for _, iface := range e.Interfaces {
		if iface.Up && !iface.Loopback && iface.IPv6 {
			return true
		}
	}
	return false
}
