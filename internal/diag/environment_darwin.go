package diag

import (
	"context"
	"net/netip"
	"time"
)

func inspectWindows(_ context.Context, _ *Environment) {}

func routeSignature(ctx context.Context, ip netip.Addr) string {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	family := "-inet"
	if ip.Is6() {
		family = "-inet6"
	}
	b, err := SystemCommand(ctx, "route", "-n", "get", family, ip.String())
	if err != nil {
		return ""
	}
	iface, gateway := routeFields(b)
	if iface == "" {
		return ""
	}
	return iface + "|" + gateway
}
