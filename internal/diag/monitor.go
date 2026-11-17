package diag

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type routeMonitorKey struct{}

type routeMonitor struct {
	mu     sync.Mutex
	peers  map[netip.Addr]string
	lookup func(context.Context, netip.Addr) string
}

func observeRoute(ctx context.Context, address net.Addr) {
	if address == nil {
		return
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		observePeerRoute(ctx, host)
	}
}

func observePeerRoute(ctx context.Context, host string) {
	monitor, _ := ctx.Value(routeMonitorKey{}).(*routeMonitor)
	if monitor == nil {
		return
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return
	}
	monitor.observe(ctx, ip)
}

func (m *routeMonitor) observe(ctx context.Context, ip netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.peers[ip]; ok || len(m.peers) >= 6 {
		return
	}
	if key := m.lookup(ctx, ip); key != "" {
		m.peers[ip] = key
	}
}

func (m *routeMonitor) changed(ctx context.Context) bool {
	m.mu.Lock()
	peers := maps.Clone(m.peers)
	m.mu.Unlock()
	for ip, previous := range peers {
		if current := m.lookup(ctx, ip); current != "" && current != previous {
			return true
		}
	}
	return false
}

func MonitorNetwork(ctx context.Context, cancel context.CancelFunc) (context.Context, func() bool) {
	routes := &routeMonitor{peers: make(map[netip.Addr]string), lookup: routeSignature}
	ctx = context.WithValue(ctx, routeMonitorKey{}, routes)
	initial := Inspect()
	var changed atomic.Bool
	stop := make(chan struct{})
	var once sync.Once
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				if ctx.Err() == nil && routes.changed(ctx) {
					changed.Store(true)
				}
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !SameNetwork(initial, Inspect()) || routes.changed(ctx) {
					changed.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	return ctx, func() bool { once.Do(func() { close(stop) }); <-done; return changed.Load() }
}
