package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	ctx    context.Context
	budget *Budget
	used   *atomic.Int64
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
	return n, nil
}

func NodeLoad(ctx context.Context, c *node.Client, phase string, streams int, duration time.Duration, budget *Budget, rate int64) Measurement {
	m := Measurement{Kind: "throughput", Target: c.Base, Status: "ok", Started: time.Now().UTC(), Data: map[string]any{"phase": phase, "streams": streams, "rate_limit_bytes_sec": rate}}
	run, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	start := time.Now()
	var downloaded, uploaded, acknowledged atomic.Int64
	var confirmedUploads atomic.Int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	failures := []string{}
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
		streamClient := c.StreamClient()
		defer func() {
			if tr, ok := streamClient.HTTP.Transport.(interface{ CloseIdleConnections() }); ok {
				tr.CloseIdleConnections()
			}
		}()
		var err error
		if direction == "download" {
			var resp *http.Response
			resp, err = streamClient.Request(run, "GET", "/v1/"+c.Session.ID+"/download", nil)
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
			reader := &budgetReader{ctx: run, budget: budget, used: &uploaded}
			var resp *http.Response
			body := io.Reader(reader)
			if rate > 0 {
				body = &pacedReader{source: reader, pace: throttle}
			}
			requestCtx, stopRequest := context.WithDeadline(ctx, start.Add(duration+time.Second))
			defer stopRequest()
			resp, err = streamClient.Request(requestCtx, "POST", "/v1/"+c.Session.ID+"/upload", body)
			if err == nil {
				defer resp.Body.Close()
				var result map[string]int64
				if json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&result) == nil {
					if n, ok := result["received_bytes"]; ok && n >= 0 {
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
	m.Data["full_interval"] = elapsed >= duration.Seconds()*0.9
	if budget.Left.Load() <= 0 {
		m.Status = "limited"
		m.Reason = "traffic_budget"
	} else if len(failures) > 0 || downloaded.Load()+uploaded.Load() == 0 {
		m.Status = "failed"
		m.Reason = "load_failed"
	}
	if m.Status == "ok" && elapsed < duration.Seconds()*0.9 {
		m.Status = "limited"
		m.Reason = "transfer_ended_early"
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
	controlBudget := min(opts.MaxBytes/8, int64(1<<20))
	if err = c.Open(ctx, opts.MaxBytes-controlBudget, 300); err != nil {
		r.Measurements = append(r.Measurements, Measurement{Kind: "node", Status: "unavailable", Reason: err.Error()})
		r.Finish(nil)
		return r
	}
	defer c.Close()
	control, err := c.NewSession(ctx, controlBudget, 300)
	if err != nil {
		r.Measurements = append(r.Measurements, Measurement{Kind: "node", Status: "unavailable", Reason: "control_session_unavailable"})
		r.Finish(ctx.Err())
		return r
	}
	defer control.Close()
	budget := NewBudget(c.Session.MaxBytes)
	for _, phase := range []string{"download", "upload"} {
		if ctx.Err() != nil || budget.Left.Load() <= 0 {
			break
		}
		if opts.Progress != nil {
			opts.Progress("Один TCP-поток: " + phase)
		}
		m := NodeLoad(ctx, c, phase, 1, 10*time.Second, budget, 0)
		m.ID = "single-" + phase
		r.Measurements = append(r.Measurements, m)
	}
	if budget.Left.Load() <= 0 {
		r.Measurements = append(r.Measurements, Measurement{Kind: "bufferbloat", Status: "unavailable", Reason: "traffic_budget"})
		r.Finish(ctx.Err())
		return r
	}
	recovery := QualityUDP(ctx, control, 10*time.Second, 128)
	recovery.ID = "recovery-single"
	r.Measurements = append(r.Measurements, recovery)
	if opts.Progress != nil {
		opts.Progress("RTT без нагрузки")
	}
	baseline := QualityUDP(ctx, control, 20*time.Second, 128)
	baseline.ID = "idle"
	r.Measurements = append(r.Measurements, baseline)
	for _, phase := range []string{"download", "upload", "both"} {
		if ctx.Err() != nil || budget.Left.Load() <= 0 {
			break
		}
		if opts.Progress != nil {
			opts.Progress("Нагрузка: " + phase)
		}
		var load Measurement
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); load = NodeLoad(ctx, c, phase, 2, 20*time.Second, budget, 0) }()
		latency := QualityUDP(ctx, control, 20*time.Second, 128)
		wg.Wait()
		load.ID = "load-" + phase
		latency.ID = "rtt-" + phase
		r.Measurements = append(r.Measurements, load, latency)
		comparison := LoadedLatency(baseline, latency, load, phase)
		r.Measurements = append(r.Measurements, comparison)
		if opts.Progress != nil {
			opts.Progress("Восстановление")
		}
		recovery := QualityUDP(ctx, control, 10*time.Second, 128)
		recovery.ID = "recovery-" + phase
		r.Measurements = append(r.Measurements, recovery)
		if comparison.Status == "ok" && number(comparison.Data["p95_increase_ms"]) >= 20 && budget.Left.Load() > 1<<20 && ctx.Err() == nil {
			bytes := number(load.Data["download_bytes"]) + number(load.Data["upload_bytes"])
			rate := int64(bytes / 20 * 0.7)
			if rate > 0 {
				if opts.Progress != nil {
					opts.Progress("Проверка ограничения нагрузки: " + phase)
				}
				var reduced Measurement
				wg.Add(1)
				go func() { defer wg.Done(); reduced = NodeLoad(ctx, c, phase, 2, 10*time.Second, budget, rate) }()
				delay := QualityUDP(ctx, control, 10*time.Second, 128)
				wg.Wait()
				reduced.ID = "limited-load-" + phase
				delay.ID = "limited-rtt-" + phase
				r.Measurements = append(r.Measurements, reduced, delay)
				limitedStats := SteadyStats(delay, 3*time.Second)
				unlimitedStats := SteadyStats(latency, 5*time.Second)
				if limitedStats.Received >= 30 {
					trial := Measurement{ID: "rate-trial-" + phase, Kind: "rate_limit_trial", Target: c.Base, Status: "inconclusive", Data: map[string]any{"phase": phase, "rate_bytes_sec": rate, "unlimited_p95_ms": unlimitedStats.P95, "limited_p95_ms": limitedStats.P95, "limited_loss_percent": limitedStats.LossPercent, "unlimited_loss_percent": unlimitedStats.LossPercent, "warmup_ms": 3000, "system_unchanged": true}}
					if reduced.Status == "ok" && delay.Status == "ok" && limitedStats.P95 < unlimitedStats.P95*0.8 && limitedStats.LossPercent <= unlimitedStats.LossPercent {
						trial.Status = "ok"
					}
					r.Measurements = append(r.Measurements, trial)
				}
			}
		}
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
		var bytes, elapsed int64
		if err == nil {
			for event := range ch {
				if event.Origin == spec.OriginClient && event.AppInfo != nil {
					bytes = event.AppInfo.NumBytes
					elapsed = event.AppInfo.ElapsedTime
				}
			}
		} else {
			m.Reason = "ndt7_start_failed"
		}
		if elapsed > 0 && bytes > 0 {
			m.Status = "ok"
			m.Data["mbps"] = float64(bytes) * 8 / float64(elapsed)
			m.Data["bytes"] = bytes
			m.Data["elapsed_us"] = elapsed
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
	if opts.Node != "" {
		c, err := node.NewClient(opts.Node, opts.NodeToken)
		if err == nil {
			err = c.Open(ctx, opts.MaxBytes, int(opts.Duration.Seconds())+60)
		}
		if err != nil {
			r.Measurements = append(r.Measurements, Measurement{Kind: "udp_rtt", Status: "unavailable", Reason: err.Error()})
		} else {
			defer c.Close()
			m := QualityUDP(ctx, c, opts.Duration, 128)
			m.ID = "quality-udp"
			r.Measurements = append(r.Measurements, m)
			for _, size := range []int{512, 1024, 1200, 1232, 1252, 1272, 1360, 1400, 1440, 1452, 1472} {
				if ctx.Err() != nil {
					break
				}
				p := QualityUDP(ctx, c, 1500*time.Millisecond, size)
				p.ID = fmt.Sprintf("packet-size-%d", size)
				p.Kind = "packet_size"
				p.Data["interpretation"] = "Проверка размера UDP payload; нижняя граница размера без фрагментации применима только если fragmentation=disabled. Тайм-аут не определяет точный PMTU."
				r.Measurements = append(r.Measurements, p)
			}
			r.Measurements = append(r.Measurements, PacketSizeAssessment(r.Measurements, c.Base))
		}
	}
	host := "ya.ru"
	if len(opts.Targets) > 0 {
		if u, e := urlParse(opts.Targets[0].URL); e == nil {
			host = u
		}
	}
	m := QualityICMP(ctx, host, opts.Duration)
	m.ID = "quality-icmp"
	r.Measurements = append(r.Measurements, m)
	if r.Environment.Gateway != "" && ctx.Err() == nil {
		g := QualityICMP(ctx, r.Environment.Gateway, min(opts.Duration, 10*time.Second))
		g.ID = "gateway-icmp"
		g.Target = "local-gateway"
		delete(g.Data, "target_ip")
		r.Measurements = append(r.Measurements, g)
	}
	r.Finish(ctx.Err())
	return r
}
