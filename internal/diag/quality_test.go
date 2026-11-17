package diag

import (
	"context"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"netdiag/internal/node"
)

func TestUDPMeasuresControlledLossAndDuplicates(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	id := "00112233445566778899aabbccddeeff"
	key := make([]byte, 32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			n, addr, e := conn.ReadFromUDP(buffer)
			if e != nil {
				return
			}
			if !node.VerifyPacket(buffer[:n], key) {
				continue
			}
			if buffer[27]%3 == 0 {
				continue
			}
			time.Sleep(5 * time.Millisecond)
			conn.WriteToUDP(buffer[:n], addr)
			if buffer[27]%3 == 1 {
				conn.WriteToUDP(buffer[:n], addr)
			}
		}
	}()
	c := &node.Client{Base: "https://fixture.invalid", Peer: "127.0.0.1", Session: node.Session{ID: id, Key: hex.EncodeToString(key), UDPPort: conn.LocalAddr().(*net.UDPAddr).Port}}
	m := QualityUDP(ctx, c, 1200*time.Millisecond, 128)
	conn.Close()
	<-done
	if m.Stats == nil || m.Stats.Sent < 10 || m.Stats.Received == 0 || m.Stats.Lost == 0 || m.Stats.Duplicates == 0 || m.Stats.Min < 4 {
		t.Fatalf("incorrect UDP statistics: %+v %+v", m, m.Stats)
	}
}

func TestBudgetRefundAndNoOverrun(t *testing.T) {
	b := NewBudget(100)
	if b.Take(60) != 60 || b.Take(60) != 40 || b.Take(1) != 0 {
		t.Fatal("budget overrun")
	}
	b.Refund(20)
	if b.Used.Load() != 80 || b.Take(30) != 20 {
		t.Fatal("incorrect refund")
	}
}

func TestUDPLateRepliesAreVisibleWithoutSuccessfulRTT(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 2048)
		for {
			n, addr, e := conn.ReadFromUDP(b)
			if e != nil {
				return
			}
			packet := append([]byte(nil), b[:n]...)
			workers.Add(1)
			go func() { defer workers.Done(); time.Sleep(800 * time.Millisecond); conn.WriteToUDP(packet, addr) }()
		}
	}()
	defer func() { conn.Close(); <-done; workers.Wait() }()
	c := &node.Client{Base: "https://fixture.invalid", Peer: "127.0.0.1", Session: node.Session{ID: "00112233445566778899aabbccddeeff", Key: hex.EncodeToString(make([]byte, 32)), UDPPort: conn.LocalAddr().(*net.UDPAddr).Port}}
	m := QualityUDP(context.Background(), c, 200*time.Millisecond, 128)
	if m.Stats == nil || m.Stats.Received != 0 || m.Stats.LateReplies == 0 {
		t.Fatalf("%+v %+v", m, m.Stats)
	}
}
