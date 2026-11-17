package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"

	"sync"
	"sync/atomic"
	"time"

	"netdiag/internal/node"

	ndt7 "github.com/m-lab/ndt7-client-go"
	"github.com/m-lab/ndt7-client-go/spec"
)

type Budget struct {
	Left atomic.Int64
	Used atomic.Int64
}

func NewBudget(n int64) *Budget { b := &Budget{}; b.Left.Store(n); return b }
func (b *Budget) Take(n int) int {
	for {
		left := b.Left.Load()
		if left <= 0 {
			return 0
		}
		take := int64(n)
		if take > left {
			take = left
		}
		if b.Left.CompareAndSwap(left, left-take) {
			b.Used.Add(take)
			return int(take)
		}
	}
}

func (b *Budget) Refund(n int) {
	if n > 0 {
		b.Left.Add(int64(n))
		b.Used.Add(-int64(n))
	}
}

type budgetReader struct {
	ctx      context.Context
	budget   *Budget
	used     *atomic.Int64
	progress func(int)
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, io.EOF
	}
	n := r.budget.Take(len(p))
	if n == 0 {
		return 0, io.EOF
	}
	clear(p[:n])
	r.used.Add(int64(n))
	if r.progress != nil {
		r.progress(n)
	}
	return n, nil
}

type transferActivity struct {
	mu          sync.Mutex
	first, last time.Time
	events      int
}

func (a *transferActivity) record(n int) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.first.IsZero() {
		a.first = now
	}
	a.last = now
	a.events++
}

func (a *transferActivity) sustained(start time.Time, duration time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	gap := min(2*time.Second, duration/3)
	return a.events >= 2 && !a.first.After(start.Add(duration/5)) && !a.last.Before(start.Add(duration-gap))
}

func NodeLoad(ctx context.Context, c *node.Client, phase string, streams int, duration time.Duration, budget *Budget, rate int64) Measurement {
	m := Measurement{Kind: "throughput", Target: c.Base, Status: "ok", Started: time.Now().UTC(), Data: map[string]any{"phase": phase, "streams": streams, "rate_limit_bytes_sec": rate}}
	if budget.Left.Load() <= 0 {
		m.Status = "limited"
		m.Reason = "traffic_budget"
		m.Data["full_interval"] = false
		m.Data["download_bytes"] = int64(0)
		m.Data["upload_bytes"] = int64(0)
		return m
	}
	run, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	start := time.Now()
	var downloaded, uploaded, acknowledged atomic.Int64
	var confirmedUploads atomic.Int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	failures := []string{}
	streamResults := []map[string]any{}
	sustained := 0
	var rateMu sync.Mutex
	var next time.Time
	throttle := func(n int) {
		if rate <= 0 {
			return
		}
		rateMu.Lock()
		now := time.Now()
		if next.Before(now) {
			next = now
		}
		at := next
		next = next.Add(time.Duration(float64(n) / float64(rate) * float64(time.Second)))
		rateMu.Unlock()
		if delay := time.Until(at); delay > 0 {
			select {
			case <-run.Done():
			case <-time.After(delay):
			}
		}
	}
	transfer := func(direction string) {
		defer wg.Done()
		activity := &transferActivity{}
		var supplied atomic.Int64
		var connection net.Conn
		var connectionMu sync.Mutex
		var tcpBefore map[string]any
		var tcpLast map[string]any
		var tcpSampled time.Time
		observe := func(n int) {
			activity.record(n)
			if n <= 0 {
				return
			}
			connectionMu.Lock()
			if connection != nil && time.Since(tcpSampled) >= time.Second {
				tcpLast = TCPStats(connection)
				tcpSampled = time.Now()
			}
			connectionMu.Unlock()
		}
		traced := func(ctx context.Context) context.Context {
			return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				connectionMu.Lock()
				connection = info.Conn
				tcpBefore = TCPStats(info.Conn)
				connectionMu.Unlock()
			}})
		}
		defer func() {
			full := activity.sustained(start, duration)
			connectionMu.Lock()
			tcpAfter := tcpLast
			if connection != nil {
				if current := TCPStats(connection); current["status"] == "ok" {
					tcpAfter = current
				}
			}
			result := map[string]any{"direction": direction, "sustained": full, "tcp_kernel_before": tcpBefore, "tcp_kernel_after": tcpAfter, "tcp_kernel_last_progress_sample_at": tcpSampled}
			connectionMu.Unlock()
			mu.Lock()
			streamResults = append(streamResults, result)
			if full {
				sustained++
			}
			mu.Unlock()
		}()
		streamClient := c.StreamClient()
		defer func() {
			if tr, ok := streamClient.HTTP.Transport.(interface{ CloseIdleConnections() }); ok {
				tr.CloseIdleConnections()
			}
		}()
		var err error
		if direction == "download" {
			var resp *http.Response
			resp, err = streamClient.Request(traced(run), "GET", "/v1/"+c.Session.ID+"/download", nil)
			if err == nil {
				defer resp.Body.Close()
				buffer := make([]byte, 32768)
				for run.Err() == nil {
					n := budget.Take(len(buffer))
					if n == 0 {
						break
					}
					read, e := resp.Body.Read(buffer[:n])
					budget.Refund(n - read)
					downloaded.Add(int64(read))
					observe(read)
					throttle(read)
					if e != nil {
						if e != io.EOF {
							err = e
						}
						break
					}
				}
			}
		} else {
			reader := &budgetReader{ctx: run, budget: budget, used: &supplied, progress: func(n int) { uploaded.Add(int64(n)); observe(n) }}
			var resp *http.Response
			body := io.Reader(reader)
			if rate > 0 {
				body = &pacedReader{source: reader, pace: throttle}
			}
			requestCtx, stopRequest := context.WithDeadline(ctx, start.Add(duration+time.Second))
			defer stopRequest()
			resp, err = streamClient.Request(traced(requestCtx), "POST", "/v1/"+c.Session.ID+"/upload", body)
			if err == nil {
				defer resp.Body.Close()
				var result map[string]int64
				if json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&result) == nil {
					if n, ok := result["received_bytes"]; ok && n > 0 && n <= supplied.Load() {
						acknowledged.Add(n)
						confirmedUploads.Add(1)
					}
				}
			}
		}
		if err != nil && run.Err() == nil {
			mu.Lock()
			failures = append(failures, "transfer_failed")
			mu.Unlock()
		}
	}
	for i := 0; i < streams; i++ {
		if phase != "upload" {
			wg.Add(1)
			go transfer("download")
		}
		if phase != "download" {
			wg.Add(1)
			go transfer("upload")
		}
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	m.DurationMS = elapsed * 1000
	m.Data["download_bytes"] = downloaded.Load()
	m.Data["upload_bytes"] = uploaded.Load()
	window := min(elapsed, duration.Seconds())
	if window > 0 && phase != "upload" && downloaded.Load() > 0 {
		m.Data["download_mbps"] = float64(downloaded.Load()) * 8 / window / 1e6
	}
	if window > 0 && phase != "download" && confirmedUploads.Load() == int64(streams) {
		m.Data["upload_mbps"] = float64(acknowledged.Load()) * 8 / window / 1e6
	}
	m.Data["measurement_window_ms"] = window * 1000
	m.Data["transport"] = "one HTTP/1.1 TCP connection per stream"
	m.Data["acknowledged_upload_bytes"] = acknowledged.Load()
	m.Data["confirmed_upload_streams"] = confirmedUploads.Load()
	m.Data["budget_exhausted"] = budget.Left.Load() <= 0
	m.Data["upload_counter_scope"] = "bytes supplied to HTTP transport; acknowledgement by the peer is not guaranteed"
	expectedStreams := streams
	if phase == "both" {
		expectedStreams *= 2
	}
	m.Data["stream_results"] = streamResults
	m.Data["sustained_streams"] = sustained
	m.Data["full_interval"] = elapsed >= duration.Seconds() && sustained == expectedStreams
	m.Data["tcp_kernel_scope"] = "socket peer; a transparent proxy may terminate TCP locally"
	if budget.Left.Load() <= 0 {
		m.Status = "limited"
		m.Reason = "traffic_budget"
	} else if len(failures) > 0 || downloaded.Load()+uploaded.Load() == 0 {
		m.Status = "failed"
		m.Reason = "load_failed"
	}
	if m.Status == "ok" && elapsed < duration.Seconds() {
		m.Status = "limited"
		m.Reason = "transfer_ended_early"
	}
	if m.Status == "ok" && sustained != expectedStreams {
		m.Status = "partial"
		m.Reason = "load_not_sustained"
	}
	if m.Status == "ok" && phase != "download" && confirmedUploads.Load() != int64(streams) {
		m.Status = "partial"
		m.Reason = "upload_not_acknowledged"
	}
	if ctx.Err() != nil {
		m.Status = "partial"
		m.Reason = "canceled_or_deadline"
	}
	return m
}

type pacedReader struct {
	source io.Reader
	pace   func(int)
}

func (r *pacedReader) Read(p []byte) (int, error) { n, e := r.source.Read(p); r.pace(n); return n, e }

func RunNodeSpeed(ctx context.Context, opts Options) Report {
	r := NewReport("speed", opts)
	c, err := node.NewClient(opts.Node, opts.NodeToken)
	if err != nil {
		r.Measurements = append(r.Measurements, Measurement{Kind: "node", Status: "unavailable", Reason: err.Error()})
		r.Finish(nil)
		return r
	}
	controlBudget := min(opts.MaxBytes/8, int64(2<<20))
	if err = c.Open(ctx, opts.MaxBytes-controlBudget, 600); err != nil {
		r.Measurements = append(r.Measurements, Measurement{Kind: "node", Status: "unavailable", Reason: err.Error()})
		r.Finish(ctx.Err())
		return r
	}
	defer c.Close()
	control, err := c.NewSession(ctx, controlBudget, 600)
	if err != nil {
		r.Measurements = append(r.Measurements, Measurement{Kind: "node", Status: "unavailable", Reason: "control_session_unavailable"})
		r.Finish(ctx.Err())
		return r
	}
	defer control.Close()
	budget := NewBudget(c.Session.MaxBytes)
	total := c.Session.MaxBytes
	weight := 10
	singles := map[string]Measurement{}
	for _, phase := range []string{"download", "upload"} {
		if ctx.Err() != nil {
			break
		}
		if opts.Progress != nil {
			opts.Progress("Один TCP-поток: " + phase)
		}
		limit := budget.Left.Load() / int64(weight)
		weight--
		m := loadWithinBudget(ctx, c, phase, 1, 10*time.Second, budget, limit, 0)
		m.ID = "single-" + phase
		singles[phase] = m
		r.Measurements = append(r.Measurements, m)
	}
	r.Measurements = append(r.Measurements, speedBudgetAssessment(singles, total))
	type trialCandidate struct {
		phase string
		rate  int64
	}
	var candidates []trialCandidate
	for _, phase := range []string{"download", "upload", "both"} {
		units := 2
		if phase == "both" {
			units = 4
		}
		if ctx.Err() != nil || budget.Left.Load() <= 0 {
			r.Measurements = append(r.Measurements, Measurement{ID: "bufferbloat-" + phase, Kind: "bufferbloat", Target: c.Base, Status: "unavailable", Reason: "traffic_budget_or_cancellation", Data: map[string]any{"phase": phase}})
			weight -= units
			continue
		}
		if opts.Progress != nil {
			opts.Progress("RTT без нагрузки: " + phase)
		}
		baseline := QualityUDP(ctx, control, 20*time.Second, 128)
		baseline.ID = "idle-" + phase
		limit := budget.Left.Load() * int64(units) / int64(weight)
		weight -= units
		if opts.Progress != nil {
			opts.Progress("Нагрузка: " + phase)
		}
		load, latency, gateway := pairedLoad(ctx, c, control, phase, 20*time.Second, budget, limit, 0, LocalGateway(r.Environment))
		gateway.ID = "gateway-load-" + phase
		load.ID = "load-" + phase
		latency.ID = "rtt-" + phase
		recovery := QualityUDP(ctx, control, 10*time.Second, 128)
		recovery.ID = "recovery-" + phase
		comparison := LoadedLatency(baseline, latency, load, phase)
		AssessRecovery(&comparison, baseline, recovery)
		r.Measurements = append(r.Measurements, baseline, load, latency, gateway, recovery, comparison)
		if comparison.Status == "ok" && number(comparison.Data["p95_increase_ms"]) >= 20 {
			rate := int64((number(load.Data["download_mbps"]) + number(load.Data["upload_mbps"])) * 1e6 / 8 * 0.7)
			if rate > 0 {
				candidates = append(candidates, trialCandidate{phase, rate})
			}
		}
	}
	remainingWeight := 0
	for _, candidate := range candidates {
		if candidate.phase == "both" {
			remainingWeight += 2
		} else {
			remainingWeight++
		}
	}
	for _, candidate := range candidates {
		units := 1
		if candidate.phase == "both" {
			units = 2
		}
		limit := budget.Left.Load() * int64(units) / int64(remainingWeight)
		remainingWeight -= units
		if opts.Progress != nil {
			opts.Progress("Проверка ограничения нагрузки: " + candidate.phase)
		}
		r.Measurements = append(r.Measurements, runRateTrial(ctx, c, control, candidate.phase, candidate.rate, budget, limit, LocalGateway(r.Environment))...)
	}
	r.Finish(ctx.Err())
	return r
}

type cappedConn struct {
	net.Conn
	budget *Budget
	stop   context.CancelFunc
}

func (c *cappedConn) Read(p []byte) (int, error) {
	n := c.budget.Take(len(p))
	if n == 0 {
		c.stop()
		c.Conn.Close()
		return 0, io.EOF
	}
	read, err := c.Conn.Read(p[:n])
	c.budget.Refund(n - read)
	return read, err
}
func (c *cappedConn) Write(p []byte) (int, error) {
	n := c.budget.Take(len(p))
	if n == 0 {
		c.stop()
		c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	written, err := c.Conn.Write(p[:n])
	c.budget.Refund(n - written)
	if err == nil && written < len(p) {
		err = io.ErrShortWrite
	}
	return written, err
}

func RunMLab(ctx context.Context, opts Options) Report {
	r := NewReport("speed", opts)
	if !opts.AcceptMLab {
		r.Measurements = append(r.Measurements, Measurement{Kind: "ndt7", Status: "unavailable", Reason: "mlab_consent_required"})
		r.Finish(nil)
		return r
	}
	run, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	budget := NewBudget(opts.MaxBytes)
	client := ndt7.NewClient("netdiag", Version)
	var mu sync.Mutex
	connections := []net.Conn{}
	client.Dialer.Proxy = nil
	client.Dialer.NetDialContext = func(c context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(c, network, addr)
		if err != nil {
			return nil, err
		}
		wrapped := &cappedConn{Conn: conn, budget: budget, stop: cancel}
		mu.Lock()
		connections = append(connections, wrapped)
		mu.Unlock()
		return wrapped, nil
	}
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-run.Done():
			mu.Lock()
			for _, conn := range connections {
				conn.Close()
			}
			mu.Unlock()
		case <-closed:
		}
	}()
	for _, phase := range []string{"download", "upload"} {
		if run.Err() != nil {
			break
		}
		if opts.Progress != nil {
			opts.Progress("M-Lab: " + phase)
		}
		start := time.Now()
		var ch <-chan spec.Measurement
		var err error
		if phase == "download" {
			ch, err = client.StartDownload(run)
		} else {
			ch, err = client.StartUpload(run)
		}
		m := Measurement{ID: "ndt7-" + phase, Kind: "ndt7", Status: "failed", Started: start.UTC(), Data: map[string]any{"phase": phase, "single_stream": true, "provider": "M-Lab", "public_measurement": true}}

		if err == nil {
			populateNDT(&m, phase, ch)
		} else {
			m.Reason = "ndt7_start_failed"
		}

		if budget.Left.Load() <= 0 {
			m.Status = "limited"
			m.Reason = "traffic_budget"
		} else if run.Err() != nil {
			m.Status = "partial"
			m.Reason = "canceled_or_deadline"
		}
		m.Target = client.FQDN
		m.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		r.Measurements = append(r.Measurements, m)
	}
	r.Measurements = append(r.Measurements, Measurement{Kind: "bufferbloat", Status: "unavailable", Reason: "controlled_node_required_for_comparable_udp_rtt_and_duplex_load", Data: map[string]any{"next": "Укажите свой --node для сопоставимых замеров задержки и двусторонней нагрузки"}})
	r.Finish(run.Err())
	return r
}

func RunQuality(ctx context.Context, opts Options) Report {
	r := NewReport("quality", opts)
	var c *node.Client
	if opts.Node != "" {
		var err error
		c, err = node.NewClient(opts.Node, opts.NodeToken)
		if err == nil {
			err = c.Open(ctx, opts.MaxBytes, int(opts.Duration.Seconds())+120)
		}
		if err != nil {
			r.Measurements = append(r.Measurements, Measurement{Kind: "udp_rtt", Status: "unavailable", Reason: err.Error()})
			c = nil
		} else {
			defer c.Close()
		}
	}
	host := "ya.ru"
	if len(opts.Targets) > 0 {
		if u, e := urlParse(opts.Targets[0].URL); e == nil {
			host = u
		}
	}
	var icmp, udp, gateway Measurement
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); icmp = QualityICMP(ctx, host, opts.Duration); icmp.ID = "quality-icmp" }()
	if address := LocalGateway(r.Environment); address != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gateway = QualityICMP(ctx, address, opts.Duration)
			gateway.ID = "gateway-icmp"
			gateway.Target = "local-gateway"
			delete(gateway.Data, "target_ip")
		}()
	}
	if c != nil {
		wg.Add(1)
		go func() { defer wg.Done(); udp = QualityUDP(ctx, c, opts.Duration, 128); udp.ID = "quality-udp" }()
	}
	wg.Wait()
	r.Measurements = append(r.Measurements, icmp)
	if gateway.ID != "" {
		r.Measurements = append(r.Measurements, gateway)
	}
	if c != nil {
		r.Measurements = append(r.Measurements, udp)
		sizes := []int{512, 1472, 1024, 1452, 1200, 1440, 1232, 1400, 1252, 1360, 1272}
		for round := 0; round < 3 && ctx.Err() == nil; round++ {
			for index := range sizes {
				if ctx.Err() != nil {
					break
				}
				at := index
				if round%2 == 1 {
					at = len(sizes) - 1 - index
				}
				size := sizes[at]
				p := QualityUDP(ctx, c, 1100*time.Millisecond, size)
				p.ID = fmt.Sprintf("packet-size-%d-round-%d", size, round+1)
				p.Kind = "packet_size"
				p.Data["round"] = round + 1
				p.Data["interpretation"] = "UDP payload с чередованием размеров; точный PMTU не определяется тайм-аутом"
				r.Measurements = append(r.Measurements, p)
			}
		}
		r.Measurements = append(r.Measurements, PacketSizeAssessment(r.Measurements, c.Base))
	}
	r.Finish(ctx.Err())
	return r
}
