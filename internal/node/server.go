package node

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type state struct {
	Session   Session
	Key       []byte
	Peer      string
	Used      int64
	Streams   int
	UDPWindow time.Time
	UDPCount  int
}

type Server struct {
	Token    string
	Caps     Capabilities
	mu       sync.Mutex
	sessions map[string]*state
}

func NewServer(token string, udpPort int, maxBytes int64) *Server {
	return &Server{Token: token, Caps: Capabilities{Version: 1, UDPPort: udpPort, HTTP3: true, MaxBytes: maxBytes, MaxSeconds: 600, MaxStreams: 8}, sessions: map[string]*state{}}
}

func (s *Server) expireLocked() {
	now := time.Now().Unix()
	for id, st := range s.sessions {
		if st.Session.Expires <= now {
			delete(s.sessions, id)
		}
	}
}

func peerIP(remote string) string { host, _, _ := net.SplitHostPort(remote); return host }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Token)) || len(s.Token) < 24 {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.URL.Path == "/v1/capabilities" && r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Caps)
		return
	}
	if r.URL.Path == "/v1/session" && r.Method == "POST" {
		var spec SessionRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&spec) != nil || spec.MaxBytes <= 0 || spec.Seconds <= 0 {
			http.Error(w, "invalid request", 400)
			return
		}
		if spec.MaxBytes > s.Caps.MaxBytes {
			spec.MaxBytes = s.Caps.MaxBytes
		}
		if spec.Seconds > s.Caps.MaxSeconds {
			spec.Seconds = s.Caps.MaxSeconds
		}
		identifier := make([]byte, 16)
		key := make([]byte, 32)
		if _, e := rand.Read(identifier); e != nil {
			http.Error(w, "entropy unavailable", 503)
			return
		}
		if _, e := rand.Read(key); e != nil {
			http.Error(w, "entropy unavailable", 503)
			return
		}
		st := &state{Session: Session{ID: hex.EncodeToString(identifier), Key: hex.EncodeToString(key), Expires: time.Now().Add(time.Duration(spec.Seconds) * time.Second).Unix(), MaxBytes: spec.MaxBytes, UDPPort: s.Caps.UDPPort}, Key: key, Peer: peerIP(r.RemoteAddr)}
		s.mu.Lock()
		s.expireLocked()
		if len(s.sessions) >= 16 {
			s.mu.Unlock()
			http.Error(w, "busy", 429)
			return
		}
		s.sessions[st.Session.ID] = st
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(st.Session)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "v1" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	s.expireLocked()
	st := s.sessions[parts[1]]
	if st == nil || st.Peer != peerIP(r.RemoteAddr) {
		s.mu.Unlock()
		http.Error(w, "invalid session", 403)
		return
	}
	if st.Streams >= s.Caps.MaxStreams {
		s.mu.Unlock()
		http.Error(w, "too many streams", 429)
		return
	}
	if parts[2] == "close" && r.Method == "POST" {
		delete(s.sessions, parts[1])
		s.mu.Unlock()
		w.WriteHeader(204)
		return
	}
	st.Streams++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); st.Streams--; s.mu.Unlock() }()
	deadline := time.Unix(st.Session.Expires, 0)
	if d := time.Now().Add(25 * time.Second); d.Before(deadline) {
		deadline = d
	}
	controller := http.NewResponseController(w)
	controller.SetReadDeadline(deadline)
	controller.SetWriteDeadline(deadline)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	reserve := func(n int) int {
		s.mu.Lock()
		defer s.mu.Unlock()
		left := st.Session.MaxBytes - st.Used
		if left <= 0 {
			return 0
		}
		if int64(n) > left {
			n = int(left)
		}
		st.Used += int64(n)
		return n
	}
	switch {
	case parts[2] == "download" && r.Method == "GET":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Encoding", "identity")
		buffer := make([]byte, 32768)
		rand.Read(buffer)
		for ctx.Err() == nil {
			n := reserve(len(buffer))
			if n == 0 {
				return
			}
			if _, err := w.Write(buffer[:n]); err != nil {
				return
			}
		}
	case parts[2] == "upload" && r.Method == "POST":
		buffer := make([]byte, 32768)
		var total int64
		for ctx.Err() == nil {
			n := reserve(len(buffer))
			if n == 0 {
				break
			}
			read, err := r.Body.Read(buffer[:n])
			total += int64(read)
			if err != nil {
				if err != io.EOF {
					return
				}
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{"received_bytes": total})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) ServeUDP(ctx context.Context, conn *net.UDPConn) error {
	buffer := make([]byte, 2048)
	for ctx.Err() == nil {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n < HeaderSize || n > MaxPacket {
			continue
		}
		id := hex.EncodeToString(buffer[4:20])
		s.mu.Lock()
		s.expireLocked()
		st := s.sessions[id]
		allowed := st != nil && st.Peer == addr.IP.String()
		if allowed && VerifyPacket(buffer[:n], st.Key) {
			if time.Since(st.UDPWindow) >= time.Second {
				st.UDPWindow = time.Now()
				st.UDPCount = 0
			}
			allowed = st.UDPCount < 20 && st.Used+int64(n*2) <= st.Session.MaxBytes
			if allowed {
				st.UDPCount++
				st.Used += int64(n * 2)
			}
		} else {
			allowed = false
		}
		s.mu.Unlock()
		if allowed {
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			conn.WriteToUDP(buffer[:n], addr)
		}
	}
	return nil
}
