package diag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

func routeFields(output []byte) (string, string) {
	var iface, gateway string
	for _, line := range strings.Split(string(output), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch strings.TrimSuffix(f[0], ":") {
		case "interface":
			iface = f[1]
		case "gateway":
			gateway = f[1]
		}
	}
	return iface, gateway
}

func discoverPhysical(ctx context.Context, e *Environment) {
	if e.PhysicalGateway != "" {
		return
	}
	eligible := map[string]bool{}
	for _, iface := range e.Interfaces {
		if iface.Up && !iface.Loopback && !iface.VPNHint && iface.IPv4 {
			eligible[iface.Name] = true
		}
	}
	if eligible[e.ActiveInterface] && validGateway(e.Gateway) {
		e.PhysicalInterface = e.ActiveInterface
		e.PhysicalGateway = e.Gateway
		return
	}
	names := make([]string, 0, len(eligible))
	for name := range eligible {
		names = append(names, name)
	}
	sort.Strings(names)
	switch runtime.GOOS {
	case "darwin":
		for _, name := range names {
			b, err := SystemCommand(ctx, "route", "-n", "get", "-ifscope", name, "default")
			if err != nil {
				continue
			}
			iface, gateway := routeFields(b)
			if iface == name && validGateway(gateway) {
				e.PhysicalInterface = iface
				e.PhysicalGateway = gateway
				return
			}
		}
	case "linux":
		b, err := SystemCommand(ctx, "ip", "-j", "route", "show", "table", "all")
		if err != nil {
			return
		}
		var routes []struct {
			Dst, Dev, Gateway string
			Metric            int
		}
		if json.Unmarshal(b, &routes) != nil {
			return
		}
		sort.SliceStable(routes, func(i, j int) bool { return routes[i].Metric < routes[j].Metric })
		for _, r := range routes {
			if r.Dst == "default" && eligible[r.Dev] && validGateway(r.Gateway) {
				e.PhysicalInterface = r.Dev
				e.PhysicalGateway = r.Gateway
				return
			}
		}

	}
}

func dnsFingerprint(ctx context.Context) string {
	var b []byte
	var err error
	switch runtime.GOOS {
	case "darwin":
		b, err = SystemCommand(ctx, "scutil", "--dns")
	case "windows":
		b, err = SystemCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Compress")
	case "linux":
		b, err = os.ReadFile("/etc/resolv.conf")
		if extra, e := SystemCommand(ctx, "resolvectl", "dns"); e == nil {
			b = append(b, extra...)
			err = nil
		}
	}
	if err != nil || len(b) == 0 {
		return ""
	}
	if runtime.GOOS == "darwin" {
		var selected []string
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "nameserver[") || strings.Contains(line, "domain") || strings.Contains(line, "if_index") || strings.Contains(line, "order") {
				selected = append(selected, strings.TrimSpace(line))
			}
		}
		b = []byte(strings.Join(selected, "\n"))
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

func validGateway(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
}

func LocalGateway(e Environment) string {
	if validGateway(e.PhysicalGateway) {
		return e.PhysicalGateway
	}
	for _, iface := range e.Interfaces {
		if iface.Name == e.ActiveInterface && iface.VPNHint {
			return ""
		}
	}
	if validGateway(e.Gateway) {
		return e.Gateway
	}
	return ""
}
