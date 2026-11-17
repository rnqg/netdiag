package diag

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	Name, IP, DoH, DoT string
	Port               string
}

var Resolvers = []Resolver{
	{Name: "Яндекс Базовый", IP: "77.88.8.8", DoH: "https://common.dot.dns.yandex.net/dns-query", DoT: "common.dot.dns.yandex.net"},
	{Name: "Cloudflare", IP: "1.1.1.1", DoH: "https://cloudflare-dns.com/dns-query", DoT: "cloudflare-dns.com"},
	{Name: "Google", IP: "8.8.8.8", DoH: "https://dns.google/dns-query", DoT: "dns.google"},
}

func Resolve(ctx context.Context, host string) Measurement {
	m := Measurement{Target: host, Kind: "dns_system", Status: "ok", Started: time.Now().UTC(), Data: map[string]any{}}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	values := []string{}
	for _, ip := range ips {
		values = append(values, ip.IP.String())
	}
	m.Data["addresses"] = values
	if err != nil {
		m.Status = "failed"
		m.Reason = ErrorCode(err)
	} else if len(values) == 0 {
		m.Status = "failed"
		m.Reason = "dns_empty"
	}
	m.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	return m
}

func QueryDNS(ctx context.Context, host string, r Resolver, method string, qtype uint16) (Measurement, []net.IP) {
	m := Measurement{Target: host, Kind: "dns_alternative", Status: "failed", Started: time.Now().UTC(), Data: map[string]any{"resolver": r.Name, "resolver_ip": r.IP, "method": method, "qtype": dns.TypeToString[qtype]}}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	var reply *dns.Msg
	var err error
	if method == "doh" {
		tr := newDoHTransport(r.IP)
		defer tr.CloseIdleConnections()
		var protocol string
		reply, protocol, err = exchangeDoH(ctx, msg, r.DoH, tr)
		if protocol != "" {
			m.Data["http_protocol"] = protocol
		}
	} else {
		network := method
		port := "53"
		if r.Port != "" {
			port = r.Port
		}
		var tc *tls.Config
		if method == "dot" {
			network = "tcp-tls"
			port = "853"
			tc = &tls.Config{ServerName: r.DoT, MinVersion: tls.VersionTLS12}
		}
		client := &dns.Client{Net: network, Timeout: 3 * time.Second, TLSConfig: tc}
		reply, _, err = client.ExchangeContext(ctx, msg, net.JoinHostPort(r.IP, port))
		if err == nil && reply.Truncated && method == "udp" {
			client.Net = "tcp"
			reply, _, err = client.ExchangeContext(ctx, msg, net.JoinHostPort(r.IP, port))
			m.Data["tcp_fallback"] = true
		}
	}
	ips := []net.IP{}
	if err != nil {
		m.Reason = ErrorCode(err)
	} else if reply == nil || !reply.Response || reply.Id != msg.Id || len(reply.Question) != 1 || reply.Question[0].Name != msg.Question[0].Name || reply.Question[0].Qtype != qtype {
		m.Reason = "dns_invalid_response"
	} else {
		m.Data["rcode"] = dns.RcodeToString[reply.Rcode]
		for _, rr := range reply.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A)
			case *dns.AAAA:
				ips = append(ips, v.AAAA)
			}
		}
		if reply.Rcode == dns.RcodeSuccess && len(ips) > 0 {
			m.Status = "ok"
		} else {
			m.Reason = "dns_" + dns.RcodeToString[reply.Rcode]
		}
	}
	values := []string{}
	for _, ip := range ips {
		values = append(values, ip.String())
	}
	m.Data["addresses"] = values
	m.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	return m, ips
}

func newDoHTransport(ip string) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    2 * time.Second,
		MaxResponseHeaderBytes: 16384,
		ForceAttemptHTTP2:      true,
	}
}

func exchangeDoH(ctx context.Context, msg *dns.Msg, endpoint string, tr *http.Transport) (*dns.Msg, string, error) {
	payload, err := msg.Pack()
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return nil, resp.Proto, err
	}
	if resp.StatusCode != http.StatusOK || len(data) > 65536 {
		return nil, resp.Proto, io.ErrUnexpectedEOF
	}
	reply := new(dns.Msg)
	err = reply.Unpack(data)
	return reply, resp.Proto, err
}
