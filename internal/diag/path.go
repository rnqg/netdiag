package diag

import (
	"context"
	"net"
	"net/url"
	"runtime"
	"strconv"
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

func Trace(ctx context.Context, host string) (m Measurement) {
	m = Measurement{ID: "trace", Kind: "traceroute", Target: host, Status: "unavailable", Started: time.Now().UTC(), Data: map[string]any{"max_hops": 12, "interpretation": "Путь диагностических проб может отличаться от TCP/QUIC. Пропуски ответов отдельных узлов не доказывают потери транзитного трафика."}}
	start := time.Now()
	defer func() { m.DurationMS = float64(time.Since(start).Microseconds()) / 1000 }()
	run, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	lookup, cancelLookup := context.WithTimeout(run, 2*time.Second)
	addresses, lookupErr := net.DefaultResolver.LookupIPAddr(lookup, host)
	cancelLookup()
	if lookupErr != nil || len(addresses) == 0 {
		m.Reason = "traceroute_dns_unavailable"
		return m
	}
	target := addresses[0].IP
	for _, address := range addresses {
		if address.IP.To4() != nil {
			target = address.IP
			break
		}
	}
	expected := []net.IP{target}
	var output []byte
	var err error
	if runtime.GOOS == "windows" {
		output, err = SystemCommand(run, "tracert.exe", "-d", "-h", "12", "-w", "800", target.String())
	} else {
		command := "traceroute"
		args := []string{"-n", "-m", "12", "-q", "1", "-w", "1", target.String()}
		if target.To4() == nil {
			if runtime.GOOS == "darwin" {
				command = "traceroute6"
			} else {
				args = append([]string{"-6"}, args...)
			}
		}
		output, err = SystemCommand(run, command, args...)
	}
	if err != nil && len(output) == 0 {
		m.Reason = "traceroute_unavailable_or_permission"
		return m
	}
	rows, replies, reached := traceRows(output, expected)
	m.Data["hops"] = rows
	m.Data["responding_hops"] = replies
	m.Data["destination_reached"] = reached
	m.Status = "ok"
	if !reached {
		m.Status = "inconclusive"
		m.Reason = "destination_not_observed"
	}
	if replies == 0 {
		m.Reason = "traceroute_no_replies"
	}
	if err != nil {
		m.Data["command_completed"] = false
	} else {
		m.Data["command_completed"] = true
	}
	if run.Err() != nil {
		m.Status = "partial"
		m.Reason = "traceroute_deadline"
	}

	return m
}

func traceRows(output []byte, expected []net.IP) ([]string, int, bool) {
	rows := []string{}
	replies := 0
	reached := false
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		responded := false
		for i, field := range fields {
			token := strings.Trim(field, "()[],")
			if ip := net.ParseIP(token); ip != nil {
				responded = true
				for _, target := range expected {
					if ip.Equal(target) {
						reached = true
					}
				}
				if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					fields[i] = "local-hop"
				}
			}
		}
		if responded {
			replies++
		}
		rows = append(rows, strings.Join(fields, " "))
	}
	return rows, replies, reached
}
