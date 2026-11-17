package diag

import (
	"context"
	"net"
	"time"
)

func qualityICMPFallback(_ context.Context, _ net.IP, _ time.Duration, m Measurement) Measurement {
	m.Status = "unavailable"
	m.Reason = "icmp_socket_permission_or_platform"
	return m
}
