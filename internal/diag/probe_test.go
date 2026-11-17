package diag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestProbeHTTPAndProtocolNegotiation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted":
			w.WriteHeader(403)
		case "/redirect":
			w.Header().Set("Location", "http://unvisited.invalid/")
			w.WriteHeader(302)
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer server.Close()
	for _, tc := range []struct{ path, status string }{{"/", "ok"}, {"/restricted", "restricted"}, {"/redirect", "ok"}} {
		m := Probe(context.Background(), Target{URL: server.URL + tc.path}, ProbeConfig{Protocol: "h1"})
		if m.Status != tc.status {
			t.Fatalf("%s: %+v", tc.path, m)
		}
		if tc.path == "/redirect" && m.Data["redirect"] != true {
			t.Fatal("redirect lost")
		}
	}
	m := Probe(context.Background(), Target{URL: server.URL}, ProbeConfig{Protocol: "h2"})
	if m.Status != "unavailable" || m.Reason != "protocol_not_negotiated" {
		t.Fatalf("unsupported h2 misclassified: %+v", m)
	}
}

func TestTLSVerificationAndHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	m := Probe(context.Background(), Target{URL: server.URL}, ProbeConfig{})
	if m.Status != "failed" || m.Reason != "tls_unknown_authority" {
		t.Fatalf("untrusted certificate accepted: %+v", m)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	m = Probe(context.Background(), Target{URL: server.URL}, ProbeConfig{Protocol: "h2", Roots: roots})
	if m.Status != "ok" || m.Data["protocol"] != "HTTP/2.0" {
		t.Fatalf("h2 failed: %+v", m)
	}
	if m.Data["body_sample_bytes"] != int64(2) || m.Data["tcp_kernel_body_offset_bytes"] != int64(2) || m.Data["tcp_kernel_after_body"] == nil {
		t.Fatalf("missing TCP sample after reading body: %+v", m)
	}
	m = Probe(context.Background(), Target{URL: server.URL}, ProbeConfig{Protocol: "h1", Roots: roots, TLSVersion: tls.VersionTLS12})
	if m.Status != "ok" || m.Data["protocol"] != "HTTP/1.1" || m.Data["tls_version"] != "TLS 1.2" {
		t.Fatalf("h1/TLS12 failed: %+v", m)
	}
}

func TestProbeCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	m := Probe(ctx, Target{URL: server.URL}, ProbeConfig{})
	if m.Status != "failed" || time.Since(start) > time.Second {
		t.Fatalf("cancel failed: %+v", m)
	}
}

func TestHTTP3ActuallyNegotiates(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "h3") })}
	done := make(chan error, 1)
	go func() { done <- server.Serve(packet) }()
	defer func() { server.Close(); packet.Close(); <-done }()
	m := Probe(context.Background(), Target{URL: "https://" + packet.LocalAddr().String() + "/"}, ProbeConfig{Protocol: "h3", Addresses: []net.IP{net.ParseIP("127.0.0.1")}, Roots: roots})
	if m.Status != "ok" || m.Data["protocol"] != "HTTP/3.0" {
		t.Fatalf("h3 failed: %+v", m)
	}
}

func TestRedirectLoopIsNotReportedAsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", 302) }))
	defer server.Close()
	m := Probe(context.Background(), Target{URL: server.URL + "/"}, ProbeConfig{})
	if m.Status != "failed" || m.Reason != "redirect_loop" {
		t.Fatalf("redirect loop accepted: %+v", m)
	}
}

func TestAltSvcPortParsing(t *testing.T) {
	for _, tc := range []struct{ input, port string }{{`h3=":8443"; ma=60`, "8443"}, {`h2=":443", h3=":443"`, "443"}, {`h3="other.example:443"`, ""}, {`h3=":99999"`, ""}} {
		if got := h3Port(tc.input); got != tc.port {
			t.Fatalf("%s => %s", tc.input, got)
		}
	}
}

func TestRedirectPropagatesRestrictedFinalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/second-hop", 302)
			return
		}
		if r.URL.Path == "/second-hop" {
			w.Header().Set("Location", "/denied")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(403)
		io.WriteString(w, "denied")
	}))
	defer server.Close()
	m := Probe(context.Background(), Target{URL: server.URL + "/"}, ProbeConfig{})
	if m.Status != "restricted" || m.Reason != "http_403" || m.Data["final_http_status"] != 403 || m.Data["final_body_sample_bytes"] != int64(6) || m.Data["final_tcp_kernel_after_body"] == nil {
		t.Fatalf("%+v", m)
	}
}
