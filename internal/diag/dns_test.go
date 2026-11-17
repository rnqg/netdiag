package diag

import (
	"context"
	"net"
	"testing"

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
