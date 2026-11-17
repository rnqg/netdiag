package diag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"netdiag/internal/node"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func QualityUDP(ctx context.Context, c *node.Client, duration time.Duration, size int) Measurement {
	m := Measurement{Kind: "udp_rtt", Target: c.Base, Status: "ok", Started: time.Now().UTC(), Data: map[string]any{"packet_bytes": size, "interval_ms": 100, "response_timeout_ms": 750, "rtt_scope": "round_trip_echo", "fragmentation": "not_disabled"}}
	key, err := hex.DecodeString(c.Session.Key)
	if err != nil || len(key) != 32 {
		m.Status = "unavailable"
		m.Reason = "invalid_session"
		return m
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.Peer, fmt.Sprint(c.Session.UDPPort)))
	if err != nil {
		m.Status = "unavailable"
		m.Reason = "invalid_node_address"
		return m
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		m.Status = "unavailable"
		m.Reason = ErrorCode(err)
		return m
	}
	defer conn.Close()
	if err := setDontFragment(conn); err == nil {
		m.Data["fragmentation"] = "request_only"
		m.Data["request_fragmentation"] = "disabled"
		if addr.IP.To4() != nil && c.Caps.UDPNoFragment4 || addr.IP.To4() == nil && c.Caps.UDPNoFragment6 {
			m.Data["fragmentation"] = "disabled"
		}
	} else {
		m.Data["fragmentation"] = "not_disabled"
	}
	var mu sync.Mutex
	var samples []Sample
	sent := map[uint64]time.Time{}
	seen := map[uint64]bool{}
	duplicates, reordered := 0, 0
	var highest uint64
	readerCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for readerCtx.Err() == nil {
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, e := conn.Read(buffer)
			if e != nil {
				if t, ok := e.(net.Error); ok && t.Timeout() {
					continue
				}
				return
			}
			if !node.VerifyPacket(buffer[:n], key) || hex.EncodeToString(buffer[4:20]) != c.Session.ID {
				continue
			}
			seq := binary.BigEndian.Uint64(buffer[20:28])
			mu.Lock()
			at, ok := sent[seq]
			if ok {
				if seen[seq] {
					duplicates++
				} else {
					seen[seq] = true
					rtt := float64(time.Since(at).Microseconds()) / 1000
					if rtt <= 750 {
						samples[seq].OK = true
						samples[seq].RTT = rtt
						samples[seq].Error = ""
					}
					if seq < highest {
						reordered++
					}
					if seq > highest {
						highest = seq
					}
				}
			}
			mu.Unlock()
		}
	}()
	start := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	requestedEnd := time.Now().Add(duration)
	sessionLimited := false
	if c.Session.Expires > 0 {
		safeEnd := time.Unix(c.Session.Expires, 0).Add(-time.Second)
		if safeEnd.Before(requestedEnd) {
			requestedEnd = safeEnd
			sessionLimited = true
		}
	}
	sendCtx, cancel := context.WithDeadline(ctx, requestedEnd)
	defer cancel()
	var seq uint64
	for sendCtx.Err() == nil {
		if c.UDPUsed != nil {
			used := c.UDPUsed.Add(int64(size * 2))
			if used > c.Session.MaxBytes {
				c.UDPUsed.Add(-int64(size * 2))
				m.Status = "limited"
				m.Reason = "traffic_budget"
				break
			}
		}
		at := time.Now()
		packet, e := node.Packet(c.Session.ID, key, seq, size)
		if e != nil {
			m.Status = "unavailable"
			m.Reason = "invalid_packet_size"
			break
		}
		mu.Lock()
		sent[seq] = at
		samples = append(samples, Sample{Sequence: int(seq), At: at.UTC(), Error: "response_timeout", Size: size})
		mu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, e = conn.Write(packet)
		if e != nil {
			mu.Lock()
			samples[seq].Error = ErrorCode(e)
			mu.Unlock()
		}
		seq++
		select {
		case <-sendCtx.Done():
		case <-ticker.C:
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(750 * time.Millisecond):
	}
	stop()
	conn.SetReadDeadline(time.Now())
	<-done
	mu.Lock()
	m.Samples = append([]Sample(nil), samples...)
	mu.Unlock()
	stats := Summarize(m.Samples)
	stats.Duplicates = duplicates
	stats.Reordered = reordered
	m.Stats = &stats
	if len(samples) == 0 && m.Status == "ok" {
		m.Status = "unavailable"
		m.Reason = "no_samples"
	} else if stats.Received == 0 && m.Status == "ok" {
		m.Status = "failed"
		m.Reason = "no_udp_replies"
	}
	if ctx.Err() != nil {
		m.Status = "partial"
		m.Reason = "canceled_or_deadline"
	}
	if sessionLimited {
		m.Status = "partial"
		m.Reason = "session_window_too_short"
	}
	m.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	return m
}

func QualityICMP(ctx context.Context, host string, duration time.Duration) Measurement {
	m := Measurement{Kind: "icmp_rtt", Target: host, Status: "ok", Started: time.Now().UTC(), Data: map[string]any{"interval_ms": 1000, "response_timeout_ms": 900}}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip4", host)
	cancel()
	if err != nil || len(ips) == 0 {
		m.Status = "unavailable"
		m.Reason = "no_ipv4_target"
		return m
	}
	m.Data["target_ip"] = ips[0].String()
	start := time.Now()
	run, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return qualityICMPFallback(ctx, ips[0], duration, m)
	}
	defer conn.Close()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	for seq := 0; run.Err() == nil; seq++ {
		at := time.Now()
		sample := Sample{Sequence: seq, At: at.UTC(), Error: "response_timeout"}
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1731, Seq: seq % 65536, Data: nonce}}
		wire, _ := msg.Marshal(nil)
		conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, err = conn.WriteTo(wire, &net.UDPAddr{IP: ips[0]})
		if err == nil {
			deadline := at.Add(900 * time.Millisecond)
			if d, ok := run.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			conn.SetReadDeadline(deadline)
			for run.Err() == nil {
				buffer := make([]byte, 1500)
				n, peer, e := conn.ReadFrom(buffer)
				if e != nil {
					break
				}
				parsed, e := icmp.ParseMessage(1, buffer[:n])
				if e != nil || parsed.Type != ipv4.ICMPTypeEchoReply {
					continue
				}
				echo, ok := parsed.Body.(*icmp.Echo)
				if !ok || echo.Seq != seq%65536 || string(echo.Data) != string(nonce) {
					continue
				}
				if p, ok := peer.(*net.UDPAddr); ok && !p.IP.Equal(ips[0]) {
					continue
				}
				sample.OK = true
				sample.Error = ""
				sample.RTT = float64(time.Since(at).Microseconds()) / 1000
				break
			}
		} else {
			sample.Error = ErrorCode(err)
		}
		m.Samples = append(m.Samples, sample)
		wait := time.Until(at.Add(time.Second))
		if wait > 0 {
			select {
			case <-run.Done():
			case <-time.After(wait):
			}
		}
	}
	stats := Summarize(m.Samples)
	m.Stats = &stats
	if stats.Received == 0 {
		m.Status = "failed"
		m.Reason = "no_icmp_replies"
	}
	if ctx.Err() != nil {
		m.Status = "partial"
	}
	m.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	return m
}
