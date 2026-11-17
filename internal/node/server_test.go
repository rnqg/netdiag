package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestSessionsRequireAuthenticationAndHaveLimits(t *testing.T) {
	s := NewServer(testToken, 4444, 1024)
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1000"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/v1/capabilities", "", "wrong"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request("POST", "/v1/session", `{"max_bytes":9999999,"seconds":9999}`, testToken)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var session Session
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.MaxBytes != 1024 || session.Expires > time.Now().Add(601*time.Second).Unix() {
		t.Fatalf("limits ignored: %+v", session)
	}
	w = request("GET", "/v1/"+session.ID+"/download", "", testToken)
	if w.Body.Len() > 1024 || w.Code != 200 {
		t.Fatalf("quota: %d %d", w.Code, w.Body.Len())
	}
	w = request("GET", "/v1/"+session.ID+"/download", "", testToken)
	if w.Body.Len() != 0 {
		t.Fatal("session exceeded byte limit")
	}
	r := httptest.NewRequest("GET", "/v1/"+session.ID+"/download", nil)
	r.RemoteAddr = "192.0.2.2:1234"
	r.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("session accepted from a different source")
	}
}

func TestPacketAuthenticationCoversSizeAndPayload(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	id := "00112233445566778899aabbccddeeff"
	p, err := Packet(id, key, 42, 128)
	if err != nil || !VerifyPacket(p, key) {
		t.Fatal("packet rejected")
	}
	p[80] ^= 1
	if VerifyPacket(p, key) {
		t.Fatal("modified payload accepted")
	}
	p[80] ^= 1
	p[20] ^= 1
	if VerifyPacket(p, key) {
		t.Fatal("modified sequence accepted")
	}
	for _, size := range []int{0, HeaderSize - 1, MaxPacket + 1} {
		if _, err := Packet(id, key, 0, size); err == nil {
			t.Fatal("invalid packet size accepted")
		}
	}
}

func TestTLSClientAndUDPEcho(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	s := NewServer(testToken, udp.LocalAddr().(*net.UDPAddr).Port, 1<<20)
	https := httptest.NewTLSServer(s)
	defer https.Close()
	c, err := NewClient(https.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(https.Certificate())
	c.HTTP.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if err = c.Open(context.Background(), 65536, 10); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Peer != "127.0.0.1" || c.Session.MaxBytes != 65536 {
		t.Fatalf("%+v", c.Session)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeUDP(ctx, udp) }()
	defer func() { cancel(); udp.Close(); <-done }()
	conn, err := net.DialUDP("udp", nil, udp.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	key, _ := hex.DecodeString(c.Session.Key)
	packet, _ := Packet(c.Session.ID, key, 1, 128)
	conn.Write(packet)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatalf("echo failed: %v", err)
	}
	packet[70] ^= 1
	conn.Write(packet)
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err = conn.Read(buffer); err == nil {
		t.Fatal("forged UDP packet reflected")
	}
}

func TestClientRejectsRedirectWithoutLeakingToken(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; io.WriteString(w, "bad") }))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer server.Close()
	c, err := NewClient(server.URL, testToken)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP.Transport = server.Client().Transport
	if c.Open(context.Background(), 1024, 5) == nil {
		t.Fatal("redirect accepted")
	}
	if leaked {
		t.Fatal("token leaked to redirect")
	}
}
