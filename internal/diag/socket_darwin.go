package diag

import (
	"crypto/tls"
	"net"

	"golang.org/x/sys/unix"
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
		s, e := unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
		if e == nil {
			data = map[string]any{"status": "ok", "srtt_ms": float64(s.Srtt), "current_rtt_ms": float64(s.Rttcur), "retransmit_packets": s.Txretransmitpackets, "retransmit_bytes": s.Txretransmitbytes, "mss": s.Maxseg, "source": "TCP_CONNECTION_INFO"}
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
		if conn.RemoteAddr().(*net.UDPAddr).IP.To4() != nil {
			result = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		} else {
			result = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
		}
	})
	if err != nil {
		return err
	}
	return result
}
