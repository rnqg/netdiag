package diag

import (
	"encoding/json"
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
