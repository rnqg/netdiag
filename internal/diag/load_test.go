package diag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netdiag/internal/node"
)

func loadFixture(t *testing.T) *node.Client {
	t.Helper()
	token := "0123456789abcdef0123456789abcdef"
	service := node.NewServer(token, 4444, 4<<20)
	server := httptest.NewUnstartedServer(service)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	c, err := node.NewClient(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c.HTTP.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if err = c.Open(context.Background(), 2<<20, 30); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestNodeLoadHonorsBudgetAndAcknowledgesUpload(t *testing.T) {
	for _, phase := range []string{"download", "upload"} {
		t.Run(phase, func(t *testing.T) {
			c := loadFixture(t)
			budget := NewBudget(65536)
			m := NodeLoad(context.Background(), c, phase, 1, 2*time.Second, budget, 0)
			if budget.Used.Load() > 65536 || m.Status != "limited" {
				t.Fatalf("%+v budget=%d", m, budget.Used.Load())
			}
			if phase == "upload" && m.Data["acknowledged_upload_bytes"] != int64(65536) {
				t.Fatalf("upload not acknowledged: %+v", m)
			}
		})
	}
}

func TestNodeLoadCancellation(t *testing.T) {
	c := loadFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	m := NodeLoad(ctx, c, "both", 2, 10*time.Second, NewBudget(1<<20), 0)
	if time.Since(start) > 2*time.Second || m.Status != "partial" {
		t.Fatalf("cancellation: %+v", m)
	}
}

type stalledTransport struct{}

func (stalledTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: &stalledBody{ctx: r.Context()}, Header: make(http.Header)}, nil
}

type stalledBody struct {
	ctx  context.Context
	sent bool
}

func (b *stalledBody) Read(p []byte) (int, error) {
	if !b.sent {
		p[0] = 1
		b.sent = true
		return 1, nil
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *stalledBody) Close() error { return nil }

func TestStalledLoadIsNotACompleteInterval(t *testing.T) {
	c := &node.Client{Base: "https://fixture.invalid", HTTP: &http.Client{Transport: stalledTransport{}}}
	m := NodeLoad(context.Background(), c, "download", 1, 100*time.Millisecond, NewBudget(100000), 0)
	if m.Status == "ok" || m.Data["full_interval"] == true || m.Data["download_bytes"] != int64(1) {
		t.Fatalf("%+v", m)
	}
}

func TestPhaseBudgetPreservesRemainingPhases(t *testing.T) {
	c := loadFixture(t)
	total := NewBudget(1 << 20)
	m := loadWithinBudget(context.Background(), c, "download", 1, time.Second, total, 65536, 0)
	if total.Used.Load() != 65536 || total.Left.Load() != (1<<20)-65536 || m.Status != "limited" {
		t.Fatalf("%+v used=%d", m, total.Used.Load())
	}
}

func TestBudgetEstimateWarnsAboutFastConnections(t *testing.T) {
	values := map[string]Measurement{"download": {Data: map[string]any{"download_mbps": 500.0}}, "upload": {Data: map[string]any{"upload_mbps": 500.0}}}
	m := speedBudgetAssessment(values, 1<<30)
	if m.Data["estimated_full_test_mib"] == nil || m.Status == "ok" {
		t.Fatal(m)
	}
}

var _ io.Reader = (*stalledBody)(nil)

func TestPairedLoadUsesSeparateControlSession(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	service := node.NewServer("0123456789abcdef0123456789abcdef", udp.LocalAddr().(*net.UDPAddr).Port, 64<<20)
	server := httptest.NewTLSServer(service)
	defer server.Close()
	c, err := node.NewClient(server.URL, service.Token)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP.Transport = server.Client().Transport
	if err = c.Open(context.Background(), 32<<20, 30); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	control, err := c.NewSession(context.Background(), 1<<20, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.ServeUDP(ctx, udp) }()
	defer func() { cancel(); udp.Close(); <-done }()
	load, latency, _ := pairedLoad(context.Background(), c, control, "download", 4*time.Second, NewBudget(1<<20), 1<<20, 128<<10, "")
	if load.Status != "ok" || load.Data["full_interval"] != true || latency.Stats == nil || latency.Stats.Received < 30 {
		t.Fatalf("load=%+v latency=%+v", load, latency)
	}
}
