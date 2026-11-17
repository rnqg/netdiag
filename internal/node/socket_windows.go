package node

import (
	"golang.org/x/sys/windows"
	"net"
)

func FragmentationSupport(conn *net.UDPConn) (bool, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false, false
	}
	v4, v6 := false, false
	if raw.Control(func(fd uintptr) {
		v4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 14, 1) == nil
		v6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 14, 1) == nil
	}) != nil {
		return false, false
	}
	return v4, v6
}
