package diag

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSUDPTruncationFallsBackToTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if w.LocalAddr().Network() == "udp" {
			m.Truncated = true
		} else {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
		}
		w.WriteMsg(m)
	})
	sUDP := &dns.Server{PacketConn: udp, Handler: handler}
	sTCP := &dns.Server{Listener: tcp, Handler: handler}
	go sUDP.ActivateAndServe()
	go sTCP.ActivateAndServe()
	defer sUDP.Shutdown()
	defer sTCP.Shutdown()
	_, port, _ := net.SplitHostPort(tcp.Addr().String())
	m, ips := QueryDNS(context.Background(), "example.test", Resolver{Name: "fixture", IP: "127.0.0.1", Port: port}, "udp", dns.TypeA)
	if m.Status != "ok" || m.Data["tcp_fallback"] != true || len(ips) != 1 || ips[0].String() != "192.0.2.1" {
		t.Fatalf("%+v %v", m, ips)
	}
}

func TestDNSNXDomainIsNotTransportFailure(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	m, ips := QueryDNS(context.Background(), "absent.invalid", Resolver{IP: "127.0.0.1", Port: port}, "udp", dns.TypeA)
	if m.Reason != "dns_NXDOMAIN" || len(ips) != 0 || m.Data["rcode"] != "NXDOMAIN" {
		t.Fatalf("%+v", m)
	}
}

func TestDNSAddressDifferenceDoesNotImplyBlocking(t *testing.T) {
	r := Report{Measurements: []Measurement{{Kind: "dns_alternative", Status: "ok", Data: map[string]any{"addresses": []string{"192.0.2.2"}}}}}
	if findings := Analyze(r); len(findings) != 0 {
		t.Fatalf("unsupported diagnosis: %+v", findings)
	}
}

func TestDoHNegotiatesHTTP2AndFallsBackToHTTP1(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if h2 && r.ProtoMajor != 2 {
					http.Error(w, "HTTP/2 required", http.StatusHTTPVersionNotSupported)
					return
				}
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || r.Header.Get("Accept") != "application/dns-message" {
					http.Error(w, "invalid DNS request", http.StatusBadRequest)
					return
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				query := new(dns.Msg)
				if err := query.Unpack(data); err != nil {
					t.Error(err)
					return
				}
				reply := new(dns.Msg)
				reply.SetReply(query)
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
				wire, err := reply.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(wire)
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			tr := newDoHTransport("127.0.0.1")
			tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			defer tr.CloseIdleConnections()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			tr.TLSClientConfig.RootCAs = roots
			query := new(dns.Msg)
			query.SetQuestion("example.test.", dns.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			reply, protocol, err := exchangeDoH(ctx, query, server.URL+"/dns-query", tr)
			want := "HTTP/1.1"
			if h2 {
				want = "HTTP/2.0"
			}
			if err != nil || protocol != want || reply == nil || reply.Id != query.Id || len(reply.Answer) != 1 {
				t.Fatalf("reply=%+v protocol=%q error=%v", reply, protocol, err)
			}
			untrusted := newDoHTransport("127.0.0.1")
			untrusted.DialContext = tr.DialContext
			untrusted.TLSClientConfig.RootCAs = x509.NewCertPool()
			defer untrusted.CloseIdleConnections()
			if _, _, err := exchangeDoH(ctx, query, server.URL, untrusted); err == nil {
				t.Fatal("untrusted TLS certificate accepted")
			}
		})
	}
}
