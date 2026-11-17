package diag

import (
	"context"
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func qualityICMPFallback(ctx context.Context, ip net.IP, duration time.Duration, m Measurement) Measurement {
	dll := windows.NewLazySystemDLL("iphlpapi.dll")
	create := dll.NewProc("IcmpCreateFile")
	closeHandle := dll.NewProc("IcmpCloseHandle")
	send := dll.NewProc("IcmpSendEcho")
	h, _, _ := create.Call()
	if h == uintptr(windows.InvalidHandle) {
		m.Status = "unavailable"
		m.Reason = "icmp_api_unavailable"
		return m
	}
	defer closeHandle.Call(h)
	run, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	start := time.Now()
	address := binary.LittleEndian.Uint32(ip.To4())
	data := []byte("network-probe-01")
	for seq := 0; run.Err() == nil; seq++ {
		at := time.Now()
		reply := make([]byte, 1024)
		n, _, _ := send.Call(h, uintptr(address), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), 900)
		sample := Sample{Sequence: seq, At: at.UTC(), Error: "response_timeout"}
		if n > 0 && binary.LittleEndian.Uint32(reply[4:8]) == 0 {
			sample.OK = true
			sample.Error = ""
			sample.RTT = float64(binary.LittleEndian.Uint32(reply[8:12]))
		}
		m.Samples = append(m.Samples, sample)
		if wait := time.Until(at.Add(time.Second)); wait > 0 {
			select {
			case <-run.Done():
			case <-time.After(wait):
			}
		}
	}
	stats := Summarize(m.Samples)
	m.Stats = &stats
	m.Status = "ok"
	if stats.Received == 0 {
		m.Status = "failed"
		m.Reason = "no_icmp_replies"
	}
	m.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	return m
}
