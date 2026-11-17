package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type Client struct {
	Base, Token string
	HTTP        *http.Client
	Caps        Capabilities
	Session     Session
	Peer        string
	UDPUsed     *atomic.Int64
}

func (c *Client) NewSession(ctx context.Context, maxBytes int64, seconds int) (*Client, error) {
	next := *c
	next.Session = Session{}
	next.UDPUsed = nil
	httpClient := *c.HTTP
	if tr, ok := c.HTTP.Transport.(*http.Transport); ok {
		httpClient.Transport = tr.Clone()
	}
	next.HTTP = &httpClient
	if err := next.Open(ctx, maxBytes, seconds); err != nil {
		return nil, err
	}
	return &next, nil
}

func (c *Client) StreamClient() *Client {
	copyClient := *c
	copyHTTP := *c.HTTP
	if tr, ok := c.HTTP.Transport.(*http.Transport); ok {
		tr = tr.Clone()
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		tr.DisableKeepAlives = true
		copyHTTP.Transport = tr
	}
	copyClient.HTTP = &copyHTTP
	return &copyClient
}

func NewClient(base, token string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("узел должен быть HTTPS origin без пароля и параметров")
	}
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext, TLSHandshakeTimeout: 4 * time.Second, MaxResponseHeaderBytes: 16384}
	return &Client{Base: strings.TrimSuffix(base, "/"), Token: token, HTTP: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", "netdiag/0.1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("соединение с узлом не установлено")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("узел вернул HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func (c *Client) Open(ctx context.Context, maxBytes int64, seconds int) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var peer string
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		host, _, _ := net.SplitHostPort(info.Conn.RemoteAddr().String())
		peer = host
	}}
	resp, err := c.Request(httptrace.WithClientTrace(ctx, trace), "GET", "/v1/capabilities", nil)
	if err != nil {
		return err
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&c.Caps)
	resp.Body.Close()
	if err != nil || c.Caps.Version != 1 {
		return fmt.Errorf("несовместимый протокол узла")
	}
	if net.ParseIP(peer) == nil {
		return fmt.Errorf("адрес соединения узла не определён")
	}
	c.Peer = peer
	if tr, ok := c.HTTP.Transport.(*http.Transport); ok {
		u, _ := url.Parse(c.Base)
		port := u.Port()
		if port == "" {
			port = "443"
		}
		pinned := tr.Clone()
		tr.CloseIdleConnections()
		pinned.DialContext = func(c context.Context, _ string, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(c, "tcp", net.JoinHostPort(peer, port))
		}
		c.HTTP.Transport = pinned
	}
	body, _ := json.Marshal(SessionRequest{MaxBytes: maxBytes, Seconds: seconds})
	resp, err = c.Request(ctx, "POST", "/v1/session", bytes.NewReader(body))
	if err != nil {
		return err
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&c.Session)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("неверная сессия узла")
	}
	identifier, idErr := hex.DecodeString(c.Session.ID)
	key, keyErr := hex.DecodeString(c.Session.Key)
	if idErr != nil || keyErr != nil || len(identifier) != 16 || len(key) != 32 || c.Session.UDPPort < 1 || c.Session.UDPPort > 65535 || c.Session.MaxBytes < 1 || c.Session.MaxBytes > maxBytes || c.Session.Expires <= time.Now().Unix() {
		return fmt.Errorf("параметры сессии узла некорректны")
	}
	c.UDPUsed = &atomic.Int64{}
	return nil
}

func (c *Client) Close() {
	if c.Session.ID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if resp, err := c.Request(ctx, "POST", "/v1/"+c.Session.ID+"/close", nil); err == nil {
			resp.Body.Close()
		}
	}
	if tr, ok := c.HTTP.Transport.(interface{ CloseIdleConnections() }); ok {
		tr.CloseIdleConnections()
	}
}
