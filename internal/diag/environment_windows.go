package diag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type windowsAdapter struct {
	name     string
	metric   uint32
	physical bool
	up       bool
}

func inspectWindows(ctx context.Context, e *Environment) {
	if ctx.Err() != nil {
		return
	}
	size := uint32(15 * 1024)
	var buffer []byte
	var head *windows.IpAdapterAddresses
	loaded := false
	for attempt := 0; attempt < 3; attempt++ {
		if size == 0 || size > 16<<20 {
			return
		}
		buffer = make([]byte, size)
		head = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, head, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			e.Capabilities["windows_adapters"] = err.Error()
			return
		}
		loaded = true
		break
	}
	if !loaded || uint32(len(buffer)) < size {
		return
	}
	adapters := map[uint32]windowsAdapter{}
	var dnsState []string
	for a := head; a != nil; a = a.Next {
		index := a.IfIndex
		if index == 0 {
			index = a.Ipv6IfIndex
		}
		name := windows.UTF16PtrToString(a.FriendlyName)
		tunnel := a.IfType == 131 || a.IfType == 53
		for _, iface := range e.Interfaces {
			if uint32(iface.Index) == index {
				tunnel = tunnel || iface.VPNHint
			}
		}
		adapters[index] = windowsAdapter{name: name, metric: a.Ipv4Metric, physical: (a.IfType == 6 || a.IfType == 71) && !tunnel, up: a.OperStatus == windows.IfOperStatusUp}
		for i := range e.Interfaces {
			if uint32(e.Interfaces[i].Index) == index && tunnel {
				e.Interfaces[i].VPNHint = true
				if e.Interfaces[i].Up {
					e.VPNHint = true
				}
			}
		}
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		dnsState = append(dnsState, fmt.Sprintf("%d:%s", index, windows.UTF16PtrToString(a.DnsSuffix)))
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			dnsState = append(dnsState, fmt.Sprintf("%d:%s", index, d.Address.IP().String()))
		}
	}
	runtime.KeepAlive(buffer)
	sort.Strings(dnsState)
	hash := sha256.Sum256([]byte(strings.Join(dnsState, "|")))
	e.DNSFingerprint = hex.EncodeToString(hash[:])
	e.Capabilities["windows_adapters"] = "GetAdaptersAddresses"
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err == nil && table != nil {
		defer windows.FreeMibTable(unsafe.Pointer(table))
		e.Capabilities["windows_routes"] = "GetIpForwardTable2"
		best, physical := uint64(^uint64(0)), uint64(^uint64(0))
		for _, row := range table.Rows() {
			adapter, ok := adapters[row.InterfaceIndex]
			if !ok || !adapter.up || row.DestinationPrefix.PrefixLength != 0 || row.DestinationPrefix.Prefix.Family != windows.AF_INET {
				continue
			}
			gateway := ""
			if row.NextHop.Family == windows.AF_INET {
				address := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop))
				gateway = net.IP(address.Addr[:]).String()
			}
			metric := uint64(row.Metric) + uint64(adapter.metric)
			if metric < best {
				best = metric
				e.ActiveInterface = adapter.name
				e.Gateway = gateway
			}
			if adapter.physical && validGateway(gateway) && metric < physical {
				physical = metric
				e.PhysicalInterface = adapter.name
				e.PhysicalGateway = gateway
			}
		}
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		enabled, _, _ := key.GetIntegerValue("ProxyEnable")
		pac, _, _ := key.GetStringValue("AutoConfigURL")
		e.ProxyHint = e.ProxyHint || enabled == 1 || pac != ""
		e.ProxyStateKnown = true
	}
}

func routeSignature(ctx context.Context, ip netip.Addr) string {
	if ctx.Err() != nil {
		return ""
	}
	var address windows.Sockaddr
	if ip.Is4() {
		address = &windows.SockaddrInet4{Addr: ip.As4()}
	} else {
		address = &windows.SockaddrInet6{Addr: ip.As16()}
	}
	var index uint32
	if windows.GetBestInterfaceEx(address, &index) != nil || index == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(index), 10)
}
