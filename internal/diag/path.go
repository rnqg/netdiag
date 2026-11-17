package diag

import (
	"context"
	"net"
	"net/url"
	"runtime"
	"strings"
	"time"
)

func urlParse(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

func Trace(ctx context.Context, host string) Measurement {
	m := Measurement{ID: "trace", Kind: "traceroute", Target: host, Status: "unavailable", Started: time.Now().UTC(), Data: map[string]any{"max_hops": 12, "interpretation": "Путь диагностических проб может отличаться от TCP/QUIC. Пропуски ответов отдельных узлов не доказывают потери транзитного трафика."}}
	run, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var output []byte
	var err error
	if runtime.GOOS == "windows" {
		output, err = SystemCommand(run, "tracert.exe", "-d", "-h", "12", "-w", "800", host)
	} else {
		output, err = SystemCommand(run, "traceroute", "-n", "-m", "12", "-q", "1", "-w", "1", host)
	}
	if err != nil && len(output) == 0 {
		m.Reason = "traceroute_unavailable_or_permission"
		return m
	}
	rows := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		clean := []string{}
		for _, field := range fields {
			token := strings.Trim(field, "()[]")
			if ip := net.ParseIP(token); ip != nil {
				if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					field = "local-hop"
				}
			}
			clean = append(clean, field)
		}
		rows = append(rows, strings.Join(clean, " "))
	}
	m.Data["hops"] = rows
	m.Status = "ok"
	if run.Err() != nil {
		m.Status = "partial"
	}
	return m
}
