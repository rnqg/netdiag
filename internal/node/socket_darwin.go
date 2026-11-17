package node

import (
	"golang.org/x/sys/unix"
	"net"
)

func FragmentationSupport(conn *net.UDPConn) (bool, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false, false
	}
	v4, v6 := false, false
	if raw.Control(func(fd uintptr) {
		v4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1) == nil
		v6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1) == nil
	}) != nil {
		return false, false
	}
	return v4, v6
}
