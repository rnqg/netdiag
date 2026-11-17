package diag

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

func MonitorNetwork(ctx context.Context, cancel context.CancelFunc) func() bool {
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
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !SameNetwork(initial, Inspect()) {
					changed.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	return func() bool { once.Do(func() { close(stop) }); <-done; return changed.Load() }
}
