package diag

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestInspectionReadsRoutesWithoutExportingPrivateIdentifiers(t *testing.T) {
	e := Inspect()
	if len(e.Interfaces) == 0 {
		t.Fatal("network interfaces unavailable")
	}
	network := false
	for _, iface := range e.Interfaces {
		if iface.Up && !iface.Loopback && iface.IPv4 {
			network = true
		}
	}
	if network && !e.RouteAvailable && os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Fatal("default route unavailable on an IPv4-connected test host", e.RouteReason)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{e.ActiveInterface, e.Gateway, e.PhysicalInterface, e.PhysicalGateway, e.DNSFingerprint} {
		if private != "" && strings.Contains(string(b), private) {
			t.Fatal("private network metadata exported")
		}
	}
}

func TestLocalGatewayUsesPhysicalPathUnderTunnel(t *testing.T) {
	e := Environment{Gateway: "198.18.0.1", PhysicalGateway: "192.168.1.1"}
	if LocalGateway(e) != "192.168.1.1" {
		t.Fatal("tunnel used as physical gateway")
	}
}

func TestTunnelAndUnspecifiedGatewaysAreNotPhysicalHops(t *testing.T) {
	for _, e := range []Environment{{Gateway: "0.0.0.0"}, {Gateway: "127.0.0.1"}, {Gateway: "198.18.0.1", ActiveInterface: "utun0", Interfaces: []Interface{{Name: "utun0", VPNHint: true}}}} {
		if LocalGateway(e) != "" {
			t.Fatal("synthetic gateway accepted", e)
		}
	}
}

func TestRouteParsingDoesNotConfuseInterfaceAndGateway(t *testing.T) {
	iface, gateway := routeFields([]byte("route to: default\n gateway: 192.168.1.1\n interface: en0\n"))
	if iface != "en0" || gateway != "192.168.1.1" {
		t.Fatal(iface, gateway)
	}
}

func TestTargetRouteChangeUsesSamePeer(t *testing.T) {
	previous := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")
	routes := map[netip.Addr]string{previous: "eth0", other: "eth1"}
	monitor := routeMonitor{peers: map[netip.Addr]string{}, lookup: func(_ context.Context, ip netip.Addr) string { return routes[ip] }}
	ctx := context.Background()
	monitor.observe(ctx, previous)
	monitor.observe(ctx, other)
	delete(routes, other)
	if monitor.changed(ctx) {
		t.Fatal("unavailable lookup reported as a route change")
	}
	routes[previous] = "tun0"
	monitor.observe(ctx, previous)
	if !monitor.changed(ctx) {
		t.Fatal("route change for an existing target was missed")
	}
}
