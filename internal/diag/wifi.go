package diag

import (
	"context"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func WiFi(ctx context.Context, iface string) Measurement {
	m := Measurement{ID: "wifi", Kind: "wifi", Status: "unavailable", Reason: "radio_data_unavailable_or_permission", Started: time.Now().UTC(), Data: map[string]any{}}
	run, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if runtime.GOOS == "windows" {
		return wifiWindows(run, m)
	}
	if runtime.GOOS == "linux" {
		output, err := SystemCommand(run, "iw", "dev", iface, "link")
		if err != nil {
			return m
		}
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			for prefix, key := range map[string]string{"signal:": "rssi_dbm", "freq:": "frequency_mhz", "tx bitrate:": "tx_mbps", "rx bitrate:": "rx_mbps"} {
				if strings.HasPrefix(line, prefix) {
					fields := strings.Fields(strings.TrimPrefix(line, prefix))
					if len(fields) > 0 {
						if value, e := strconv.ParseFloat(fields[0], 64); e == nil {
							m.Data[key] = value
						}
					}
				}
			}
		}
	}
	if runtime.GOOS == "darwin" {
		output, err := SystemCommand(run, "system_profiler", "SPAirPortDataType", "-json")
		if err != nil {
			return m
		}
		var data any
		if json.Unmarshal(output, &data) != nil {
			return m
		}
		var walk func(any, bool)
		walk = func(value any, current bool) {
			switch v := value.(type) {
			case map[string]any:
				for key, item := range v {
					inside := current || strings.Contains(key, "current_network")
					if inside {
						if strings.Contains(key, "signal_noise") {
							if s, ok := item.(string); ok {
								fields := strings.Fields(s)
								if len(fields) > 0 {
									if n, e := strconv.ParseFloat(fields[0], 64); e == nil {
										m.Data["rssi_dbm"] = n
									}
								}
							}
						}
						if strings.Contains(key, "channel") {
							if s, ok := item.(string); ok {
								m.Data["channel"] = s
							}
						}
						if strings.Contains(key, "transmit_rate") || strings.Contains(key, "network_rate") {
							m.Data["tx_mbps"] = item
						}
					}
					walk(item, inside)
				}
			case []any:
				for _, item := range v {
					walk(item, current)
				}
			}
		}
		walk(data, false)
	}
	if len(m.Data) > 0 {
		m.Status = "ok"
		m.Reason = ""
	}
	return m
}
