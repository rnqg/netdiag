package diag

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"
)

func inspectWindows(_ context.Context, _ *Environment) {}

func routeSignature(ctx context.Context, ip netip.Addr) string {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	b, err := SystemCommand(ctx, "ip", "-j", "route", "get", ip.String())
	if err != nil {
		return ""
	}
	var routes []struct {
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
		Source  string `json:"prefsrc"`
	}
	if json.Unmarshal(b, &routes) != nil || len(routes) == 0 || routes[0].Dev == "" {
		return ""
	}
	r := routes[0]
	return r.Dev + "|" + r.Gateway + "|" + r.Source
}
