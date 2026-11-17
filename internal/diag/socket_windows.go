package diag

import (
	"crypto/tls"
	"encoding/binary"
	"net"

	"golang.org/x/sys/windows"
)

func TCPStats(conn net.Conn) map[string]any {
	if c, ok := conn.(*tls.Conn); ok {
		conn = c.NetConn()
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return map[string]any{"status": "unavailable"}
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return map[string]any{"status": "unavailable"}
	}
	data := map[string]any{"status": "unavailable"}
	raw.Control(func(fd uintptr) {
		version := []byte{0, 0, 0, 0}
		buffer := make([]byte, 128)
		var returned uint32
		err := windows.WSAIoctl(windows.Handle(fd), 0xD8000027, &version[0], 4, &buffer[0], uint32(len(buffer)), &returned, nil, 0)
		if err == nil && returned >= 72 {
			data = map[string]any{"status": "ok", "mss": binary.LittleEndian.Uint32(buffer[4:8]), "estimated_rtt_ms": float64(binary.LittleEndian.Uint32(buffer[20:24])) / 1000, "min_rtt_ms": float64(binary.LittleEndian.Uint32(buffer[24:28])) / 1000, "retransmit_bytes": binary.LittleEndian.Uint32(buffer[68:72]), "source": "SIO_TCP_INFO_v0"}
		}
	})
	return data
}

func setDontFragment(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	err = raw.Control(func(fd uintptr) {
		level := windows.IPPROTO_IP
		if conn.RemoteAddr().(*net.UDPAddr).IP.To4() == nil {
			level = windows.IPPROTO_IPV6
		}
		result = windows.SetsockoptInt(windows.Handle(fd), level, 14, 1)
	})
	if err != nil {
		return err
	}
	return result
}
