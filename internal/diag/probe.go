package diag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type ProbeConfig struct {
	Family        string
	Protocol      string
	TLSVersion    uint16
	Addresses     []net.IP
	Roots         *x509.CertPool
	QUICPort      string
	redirectDepth int
	redirectSeen  []string
}

func Probe(ctx context.Context, target Target, cfg ProbeConfig) Measurement {
	m := Measurement{Target: target.URL, Kind: "http", Status: "failed", Started: time.Now().UTC(), Data: map[string]any{"family": cfg.Family, "requested_protocol": cfg.Protocol}}
	data := m.Data
	start := time.Now()
	u, err := url.Parse(target.URL)
	if err != nil || u.Hostname() == "" {
		m.Reason = "invalid_target"
		return m
	}
	for _, seen := range cfg.redirectSeen {
		if seen == target.URL {
			m.Reason = "redirect_loop"
			data["failure_stage"] = "http"
			return m
		}
	}
	if cfg.redirectDepth > 3 {
		m.Reason = "redirect_limit"
		data["failure_stage"] = "http"
		return m
	}
	cfg.redirectSeen = append(append([]string(nil), cfg.redirectSeen...), target.URL)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	if cfg.Protocol == "h3" && cfg.QUICPort != "" {
		port = cfg.QUICPort
	}
	data["requested_port"] = port
	var mu sync.Mutex
	var dnsStart, tcpStart, tlsStart time.Time
	attempts := map[string]time.Time{}
	var selected net.Conn
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { mu.Lock(); dnsStart = time.Now(); mu.Unlock() },
		DNSDone: func(v httptrace.DNSDoneInfo) {
			mu.Lock()
			defer mu.Unlock()
			if !dnsStart.IsZero() {
				data["dns_ms"] = float64(time.Since(dnsStart).Microseconds()) / 1000
			}
			ips := []string{}
			for _, ip := range v.Addrs {
				ips = append(ips, ip.IP.String())
			}
			data["addresses"] = ips
			if v.Err != nil {
				data["failure_stage"] = "dns"
			}
		},
		ConnectStart: func(network, address string) {
			mu.Lock()
			tcpStart = time.Now()
			attempts[network+"|"+address] = tcpStart
			mu.Unlock()
		},
		ConnectDone: func(network, address string, e error) {
			mu.Lock()
			defer mu.Unlock()
			if at, ok := attempts[network+"|"+address]; ok {
				duration := float64(time.Since(at).Microseconds()) / 1000
				if e == nil {
					data["connect_ms"] = duration
				}
				list, _ := data["connection_attempts"].([]map[string]any)
				data["connection_attempts"] = append(list, map[string]any{"address": address, "duration_ms": duration, "ok": e == nil})
			}
			if e != nil {
				data["failure_stage"] = "tcp"
			}
		},
		TLSHandshakeStart: func() { mu.Lock(); tlsStart = time.Now(); mu.Unlock() },
		TLSHandshakeDone: func(s tls.ConnectionState, e error) {
			mu.Lock()
			defer mu.Unlock()
			if !tlsStart.IsZero() {
				data["tls_ms"] = float64(time.Since(tlsStart).Microseconds()) / 1000
			}
			if e != nil {
				data["failure_stage"] = "tls"
			} else {
				data["tls_version"] = tls.VersionName(s.Version)
				data["alpn"] = s.NegotiatedProtocol
			}
		},
		GotConn: func(i httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			if addr, ok := i.Conn.RemoteAddr().(*net.TCPAddr); ok {
				data["peer_ip"] = addr.IP.String()
			}
			selected = i.Conn
			data["tcp_kernel"] = TCPStats(i.Conn)
			data["tcp_kernel_sample_scope"] = "connection_ready"
			data["tcp_peer_scope"] = "socket_peer; local proxy or tunnel may terminate TCP"
			delete(data, "failure_stage")
		},
		GotFirstResponseByte: func() {
			mu.Lock()
			data["first_byte_ms"] = float64(time.Since(start).Microseconds()) / 1000
			mu.Unlock()
		},
	}
	network := "tcp"
	if cfg.Family == "ipv4" {
		network = "tcp4"
	}
	if cfg.Family == "ipv6" {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	dial := func(c context.Context, _ string, addr string) (net.Conn, error) {
		if len(cfg.Addresses) > 0 {
			var last error
			for _, ip := range cfg.Addresses {
				if cfg.Family == "ipv4" && ip.To4() == nil || cfg.Family == "ipv6" && ip.To4() != nil {
					continue
				}
				conn, e := dialer.DialContext(c, network, net.JoinHostPort(ip.String(), port))
				if e == nil {
					return conn, nil
				}
				last = e
			}
			if last == nil {
				last = errors.New("no address for requested family")
			}
			return nil, last
		}
		return dialer.DialContext(c, network, addr)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.Roots}
	if cfg.TLSVersion != 0 {
		tlsCfg.MinVersion = cfg.TLSVersion
		tlsCfg.MaxVersion = cfg.TLSVersion
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: true, MaxResponseHeaderBytes: 65536}
	defer transport.CloseIdleConnections()
	var rt http.RoundTripper = transport
	if cfg.Protocol == "h1" {
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if cfg.Protocol == "h3" {
		h3 := &http3.Transport{TLSClientConfig: tlsCfg, QUICConfig: &quic.Config{HandshakeIdleTimeout: 4 * time.Second, MaxIdleTimeout: 5 * time.Second}}
		if len(cfg.Addresses) > 0 {
			h3.Dial = func(c context.Context, _ string, t *tls.Config, q *quic.Config) (*quic.Conn, error) {
				t = t.Clone()
				t.ServerName = u.Hostname()
				started := time.Now()
				connection, e := quic.DialAddr(c, net.JoinHostPort(cfg.Addresses[0].String(), port), t, q)
				mu.Lock()
				data["quic_handshake_ms"] = float64(time.Since(started).Microseconds()) / 1000
				if e == nil {
					host, _, _ := net.SplitHostPort(connection.RemoteAddr().String())
					data["peer_ip"] = host
				}
				mu.Unlock()
				return connection, e
			}
		}
		defer h3.Close()
		rt = h3
	}
	client := &http.Client{Transport: rt, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", target.URL, nil)
	if err != nil {
		m.Reason = "invalid_target"
		return m
	}
	req.Header.Set("User-Agent", "netdiag/"+Version)
	req.Header.Set("Range", "bytes=0-65535")
	resp, err := client.Do(req)
	mu.Lock()
	if err != nil {
		m.Reason = ErrorCode(err)
		if _, ok := data["failure_stage"]; !ok {
			data["failure_stage"] = "http"
			if cfg.Protocol == "h3" {
				data["failure_stage"] = "quic_or_http3"
			}
		}
	} else {
		data["http_status"] = resp.StatusCode
		data["protocol"] = resp.Proto
		data["reachable"] = true
		altPort := h3Port(resp.Header.Get("Alt-Svc"))
		data["alt_svc_h3"] = altPort != ""
		data["alt_svc_h3_port"] = altPort
		if resp.TLS != nil {
			data["tls_version"] = tls.VersionName(resp.TLS.Version)
			data["certificate_verified"] = true
			if len(resp.TLS.PeerCertificates) > 0 {
				data["certificate_not_before"] = resp.TLS.PeerCertificates[0].NotBefore
				data["certificate_not_after"] = resp.TLS.PeerCertificates[0].NotAfter
			}
		}
		m.Status = "ok"
		if resp.StatusCode >= 400 {
			m.Status = "restricted"
			m.Reason = "http_" + strconv.Itoa(resp.StatusCode)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			data["redirect"] = true
			if loc, e := resp.Location(); e == nil {
				data["redirect_origin"] = loc.Scheme + "://" + loc.Host
			}
		}
		if cfg.Protocol == "h2" && resp.ProtoMajor != 2 || cfg.Protocol == "h3" && resp.ProtoMajor != 3 {
			m.Status = "unavailable"
			m.Reason = "protocol_not_negotiated"
		}
	}
	mu.Unlock()
	if resp != nil {
		mu.Lock()
		conn := selected
		mu.Unlock()
		sink := &responseSample{conn: conn}
		count, bodyErr := io.Copy(sink, io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		mu.Lock()
		data["body_sample_bytes"] = count
		if sink.stats != nil {
			data["tcp_kernel_after_body"] = sink.stats
			data["tcp_kernel_body_offset_bytes"] = sink.sampledAt
		}
		mu.Unlock()
		if bodyErr != nil && m.Status == "ok" {
			mu.Lock()
			m.Status = "failed"
			m.Reason = ErrorCode(bodyErr)
			data["failure_stage"] = "body"
			mu.Unlock()
		}
	}
	if resp != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 && m.Status == "ok" {
		if location, e := resp.Location(); e == nil && location.Scheme == u.Scheme && location.Host == u.Host && location.User == nil {
			cfg.redirectDepth++
			child := Probe(ctx, Target{Name: target.Name, URL: location.String()}, cfg)
			mu.Lock()
			data["redirect_followed"] = true
			data["redirect_status"] = child.Status
			data["final_http_status"] = child.Data["http_status"]
			if v, ok := child.Data["final_http_status"]; ok {
				data["final_http_status"] = v
			}
			if v, ok := child.Data["failure_stage"]; ok {
				data["failure_stage"] = v
			}
			if child.Status != "ok" {
				m.Status = child.Status
				m.Reason = child.Reason
			}
			mu.Unlock()
		}
	}
	mu.Lock()
	snapshot := make(map[string]any, len(data))
	for key, value := range data {
		snapshot[key] = value
	}
	mu.Unlock()
	m.Data = snapshot
	m.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	if peer, ok := snapshot["peer_ip"].(string); ok {
		observePeerRoute(ctx, peer)
	}
	return m
}

type responseSample struct {
	conn            net.Conn
	stats           map[string]any
	read, sampledAt int64
}

func (s *responseSample) Write(p []byte) (int, error) {
	s.read += int64(len(p))
	if len(p) > 0 && s.conn != nil {
		stats := TCPStats(s.conn)
		if stats["status"] == "ok" || s.stats == nil {
			s.stats = stats
			s.sampledAt = s.read
		}
	}
	return len(p), nil
}

func h3Port(value string) string {
	for _, entry := range strings.Split(value, ",") {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 || parts[0] != "h3" {
			continue
		}
		authority := strings.Trim(strings.TrimSpace(strings.SplitN(parts[1], ";", 2)[0]), "\"")
		if !strings.HasPrefix(authority, ":") {
			continue
		}
		port := strings.TrimPrefix(authority, ":")
		n, err := strconv.Atoi(port)
		if err == nil && n > 0 && n < 65536 {
			return port
		}
	}
	return ""
}

func ErrorCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "dns_not_found"
		}
		if dnsErr.IsTimeout {
			return "dns_timeout"
		}
		return "dns_error"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "tls_unknown_authority"
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "tls_hostname"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return "tls_certificate_invalid"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "connection_error"
}
