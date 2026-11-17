package diag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	server := httptest.NewTLSServer(service)
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
