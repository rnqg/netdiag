package diag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

func SystemCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.WaitDelay = time.Second
	return cmd.Output()
}

func Inspect() Environment {
	e := Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, Capabilities: map[string]string{}}
	interfaces, err := net.Interfaces()
	if err != nil {
		e.Capabilities["interfaces"] = err.Error()
	}
	var fingerprint []string
	for _, iface := range interfaces {
		fingerprint = append(fingerprint, fmt.Sprintf("%s:%d:%d", iface.Name, iface.MTU, iface.Flags))
		item := Interface{Name: iface.Name, Index: iface.Index, MTU: iface.MTU, Up: iface.Flags&net.FlagUp != 0, Loopback: iface.Flags&net.FlagLoopback != 0}
		name := strings.ToLower(iface.Name)
		for _, part := range []string{"utun", "tun", "tap", "wg", "wireguard", "tailscale", "ppp", "vpn"} {
			if strings.Contains(name, part) {
				item.VPNHint = true
			}
		}
		addresses, _ := iface.Addrs()
		for _, addr := range addresses {
			ip, _, parseErr := net.ParseCIDR(addr.String())
			if parseErr != nil {
				continue
			}
			if ip.To4() != nil {
				item.IPv4 = true
			} else if !ip.IsLinkLocalUnicast() {
				item.IPv6 = true
			}
			if item.Up {
				fingerprint = append(fingerprint, iface.Name+":"+addr.String())
			}
		}
		if item.Up && !item.Loopback {
			e.VPNHint = e.VPNHint || item.VPNHint
		}
		e.Interfaces = append(e.Interfaces, item)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if os.Getenv(key) != "" {
			e.ProxyHint = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "darwin":
		if b, err := SystemCommand(ctx, "route", "-n", "get", "default"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				f := strings.Fields(line)
				if len(f) < 2 {
					continue
				}
				switch strings.TrimSuffix(f[0], ":") {
				case "gateway":
					e.Gateway = f[1]
				case "interface":
					e.ActiveInterface = f[1]
				}
			}
		}
		if b, err := SystemCommand(ctx, "scutil", "--proxy"); err == nil {
			s := string(b)
			e.ProxyHint = e.ProxyHint || strings.Contains(s, "HTTPEnable : 1") || strings.Contains(s, "HTTPSEnable : 1") || strings.Contains(s, "SOCKSEnable : 1") || strings.Contains(s, "ProxyAutoConfigEnable : 1")
		}
	case "linux":
		if b, err := SystemCommand(ctx, "ip", "-j", "route", "show", "default"); err == nil {
			var routes []struct {
				Gateway string `json:"gateway"`
				Dev     string `json:"dev"`
				Metric  int    `json:"metric"`
			}
			if json.Unmarshal(b, &routes) == nil && len(routes) > 0 {
				sort.SliceStable(routes, func(i, j int) bool { return routes[i].Metric < routes[j].Metric })
				e.Gateway = routes[0].Gateway
				e.ActiveInterface = routes[0].Dev
			}
		}
	case "windows":
		b, err := SystemCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1; if($r){[pscustomobject]@{Gateway=$r.NextHop;Interface=$r.InterfaceAlias;Proxy=(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue).ProxyEnable}|ConvertTo-Json -Compress}")
		if err == nil {
			var v struct {
				Gateway, Interface string
				Proxy              int
			}
			if json.Unmarshal(b, &v) == nil {
				e.Gateway = v.Gateway
				e.ActiveInterface = v.Interface
				e.ProxyHint = e.ProxyHint || v.Proxy == 1
			}
		}
	}
	e.RouteAvailable = e.ActiveInterface != ""
	if !e.RouteAvailable {
		e.RouteReason = "маршрут не прочитан; доступность проверяется фактическими соединениями"
	}
	sort.Strings(fingerprint)
	linkSum := sha256.Sum256([]byte(strings.Join(fingerprint, "|")))
	e.LinkFingerprint = hex.EncodeToString(linkSum[:])
	fingerprint = append(fingerprint, e.ActiveInterface, e.Gateway, fmt.Sprint(e.ProxyHint))
	sort.Strings(fingerprint)
	sum := sha256.Sum256([]byte(strings.Join(fingerprint, "|")))
	e.Fingerprint = hex.EncodeToString(sum[:])
	e.Capabilities["wifi"] = "радио-параметры запрашиваются отдельным измерением; доступ зависит от ОС и прав"
	e.Capabilities["tcp_kernel_rtt"] = "статистика конкретного TCP-соединения запрашивается через API ОС; наличие отражено в tcp_kernel"
	return e
}

func SameNetwork(a, b Environment) bool {
	if a.LinkFingerprint != "" && b.LinkFingerprint != "" && a.LinkFingerprint != b.LinkFingerprint {
		return false
	}
	if a.RouteAvailable && b.RouteAvailable && (a.ActiveInterface != b.ActiveInterface || a.Gateway != b.Gateway) {
		return false
	}
	return true
}
