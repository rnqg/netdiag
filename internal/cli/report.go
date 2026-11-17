package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"netdiag/internal/diag"
)

func ReadReport(path string) (diag.Report, error) {
	var r diag.Report
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 32<<20))
	if err = dec.Decode(&r); err != nil {
		return r, errors.New("не удалось прочитать JSON-отчёт")
	}
	if r.Schema != diag.Schema {
		return r, fmt.Errorf("версия отчёта %d не поддерживается", r.Schema)
	}
	if len(r.Measurements) > 20000 || len(r.Targets) > 32 {
		return r, errors.New("слишком большой отчёт")
	}
	return r, nil
}

func WriteReport(path string, r diag.Report) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("отчёт не сохранён (существующий файл не перезаписывается): %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(r)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0x80 && r <= 0x9f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 || r < 32 && r != '\n' && r != '\t' || r == 127 || r == 0x202e || r == 0x202d {
			return -1
		}
		return r
	}, s)
}

type terminalWriter struct{ io.Writer }

func (w terminalWriter) Write(p []byte) (int, error) {
	value := clean(string(p))
	n, err := io.WriteString(w.Writer, value)
	if err != nil {
		return 0, err
	}
	if n != len(value) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func PrintReport(w io.Writer, r diag.Report, verbose bool) {
	w = terminalWriter{w}
	state := "завершена"
	if r.Partial {
		state = "частично завершена"
	}
	fmt.Fprintf(w, "Проверка %s. Режим: %s.\n", state, r.Mode)
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n%s\n%s\n", clean(f.Summary), clean(f.Next))
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "В выполненных проверках неисправности не обнаружены. Это не проверка всех функций приложений.")
	}
	for _, m := range r.Measurements {
		if m.Kind == "packet_size" && !verbose {
			continue
		}
		if m.Kind == "path_mtu" && m.Status == "ok" {
			fmt.Fprintf(w, "\nПодтверждённый UDP payload без фрагментации: %v байт. Точный PMTU не установлен.\n", m.Data["largest_confirmed_udp_payload_bytes"])
		}
		if m.Kind == "http_baseline" {
			fmt.Fprintf(w, "%s — %s\n", clean(m.Target), statusName(m.Status))
		}
		if m.Stats != nil {
			fmt.Fprintf(w, "\n%s: %s\nОтветы: %d/%d, без ответа: %.1f%%\n", clean(m.Kind), clean(m.Target), m.Stats.Received, m.Stats.Sent, m.Stats.LossPercent)
			if m.Stats.LocalErrors > 0 {
				fmt.Fprintf(w, "Локальных ошибок отправки: %d\n", m.Stats.LocalErrors)
			}
			if m.Stats.LateReplies > 0 {
				fmt.Fprintf(w, "Ответов после тайм-аута: %d\n", m.Stats.LateReplies)
			}
			if m.Stats.Received > 0 {
				fmt.Fprintf(w, "Медиана RTT: %.2f мс, p95: %.2f мс\n", m.Stats.Median, m.Stats.P95)
			} else {
				fmt.Fprintln(w, "RTT не измерен.")
			}
			if m.Stats.JitterPairs > 0 {
				fmt.Fprintf(w, "Джиттер RTT: %.2f мс\n", m.Stats.Jitter)
			}
		}
		if m.Kind == "throughput" || m.Kind == "ndt7" {
			fmt.Fprintf(w, "\nСкорость (%v): %s\n", m.Data["phase"], statusName(m.Status))
			for _, key := range []string{"mbps", "download_mbps", "upload_mbps"} {
				if value, ok := m.Data[key]; ok {
					label := map[string]string{"mbps": "Скорость", "download_mbps": "Загрузка", "upload_mbps": "Отдача"}[key]
					fmt.Fprintf(w, "%s: %.2f Мбит/с\n", label, toFloat(value))
				}
			}
		}
		if m.Kind == "bufferbloat" {
			fmt.Fprintf(w, "\nЗадержка под нагрузкой (%v): %s\n", m.Data["phase"], statusName(m.Status))
			if m.Data["idle_p95_ms"] != nil {
				fmt.Fprintf(w, "p95 RTT: %.2f → %.2f мс; изменение: %+.2f мс\n", toFloat(m.Data["idle_p95_ms"]), toFloat(m.Data["loaded_p95_ms"]), toFloat(m.Data["p95_increase_ms"]))
				fmt.Fprintf(w, "Без ответа: %.2f%% → %.2f%%\n", toFloat(m.Data["idle_loss_percent"]), toFloat(m.Data["loaded_loss_percent"]))
			}
		}
		if m.Kind == "speed_plan" && m.Data["estimated_full_test_mib"] != nil {
			fmt.Fprintf(w, "\nОценка данных для полного теста: %.0f МиБ; лимит узла: %.0f МиБ.\n", toFloat(m.Data["estimated_full_test_mib"]), toFloat(m.Data["available_mib"]))
			if m.Status == "inconclusive" {
				fmt.Fprintf(w, "Для полного теста увеличьте --max-mib на клиенте и узле; текущий лимит сохранён.\n")
			}
		}
		if m.Kind == "comparison" {
			fmt.Fprintf(w, "\n%s (%v): %v → %v\n", clean(m.Target), m.Data["kind"], m.Data["before"], m.Data["after"])
			before, _ := m.Data["before_values"].(map[string]any)
			after, _ := m.Data["after_values"].(map[string]any)
			for _, key := range []string{"first_byte_ms", "p95_ms", "jitter_ms", "loss_percent", "mbps", "download_mbps", "upload_mbps"} {
				if old, ok := before[key]; ok {
					if current, present := after[key]; present {
						labels := map[string]string{"first_byte_ms": "Первый байт, мс", "p95_ms": "p95 RTT, мс", "jitter_ms": "Джиттер, мс", "loss_percent": "Без ответа, %", "mbps": "Скорость, Мбит/с", "download_mbps": "Загрузка, Мбит/с", "upload_mbps": "Отдача, Мбит/с"}
						fmt.Fprintf(w, "%s: %.2f → %.2f\n", labels[key], toFloat(old), toFloat(current))
					}
				}
			}
		}
		if m.Status == "unavailable" {
			if verbose {
				fmt.Fprintf(w, "Не измерено %s: %s\n", clean(m.Kind), clean(m.Reason))
			}
		}
		if verbose {
			fmt.Fprintf(w, "\n[%s] %s %s: %s (%s)\n", clean(m.ID), clean(m.Kind), clean(m.Target), clean(m.Status), clean(m.Reason))
			if len(m.Data) > 0 {
				data, _ := json.Marshal(m.Data)
				fmt.Fprintln(w, string(data))
			}
		}
	}
	printCoverage(w, r.Measurements)
	if !verbose {
		missing := 0
		for _, m := range r.Measurements {
			if m.Status == "unavailable" {
				missing++
			}
		}
		if missing > 0 {
			fmt.Fprintf(w, "\nНедоступных измерений: %d. Причины доступны с --verbose или в JSON.\n", missing)
		}
	}
}

func statusName(status string) string {
	names := map[string]string{"ok": "ответ получен", "failed": "проверка не прошла", "restricted": "сервер ограничил запрос", "partial": "измерено частично", "limited": "достигнуто ограничение теста", "unavailable": "измерение недоступно", "inconclusive": "данных недостаточно"}
	if name, ok := names[status]; ok {
		return name
	}
	return clean(status)
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	}
	return 0
}

func comparisonKey(m diag.Measurement) string {
	identity := []any{m.Kind, m.Target}
	for _, key := range []string{"family", "requested_protocol", "requested_tls", "resolver", "method", "qtype", "resolver_family", "negative_control", "phase", "packet_bytes", "round"} {
		identity = append(identity, m.Data[key])
	}
	b, _ := json.Marshal(identity)
	return string(b)
}

func comparisonValues(m diag.Measurement) map[string]any {
	values := map[string]any{"duration_ms": m.DurationMS}
	for _, key := range []string{"dns_ms", "connect_ms", "tls_ms", "first_byte_ms", "protocol", "tls_version", "http_status", "final_http_status", "mbps", "download_mbps", "upload_mbps", "idle_p95_ms", "loaded_p95_ms", "p95_increase_ms", "rssi_dbm", "tx_mbps", "rx_mbps", "channel"} {
		if value, ok := m.Data[key]; ok {
			values[key] = value
		}
	}
	if m.Stats != nil {
		values["loss_percent"] = m.Stats.LossPercent
		if m.Stats.Received > 0 {
			values["median_ms"] = m.Stats.Median
			values["p95_ms"] = m.Stats.P95
		}
		if m.Stats.JitterPairs > 0 {
			values["jitter_ms"] = m.Stats.Jitter
		}
	}
	return values
}

func Compare(before diag.Report, after *diag.Report) {
	accepted := map[string]bool{"http_baseline": true, "dns_system": true, "dns_alternative": true, "ip_family": true, "protocol": true, "tls_version": true, "wifi": true, "icmp_rtt": true, "udp_rtt": true, "throughput": true, "ndt7": true, "bufferbloat": true, "path_mtu": true}
	indexed := map[string][]diag.Measurement{}
	for _, m := range after.Measurements {
		if accepted[m.Kind] {
			key := comparisonKey(m)
			indexed[key] = append(indexed[key], m)
		}
	}
	used := map[string]int{}
	for _, old := range before.Measurements {
		if !accepted[old.Kind] {
			continue
		}
		key := comparisonKey(old)
		matches := indexed[key]
		index := used[key]
		if index >= len(matches) {
			continue
		}
		current := matches[index]
		used[key]++
		status := "ok"
		if old.Status != current.Status || old.Reason != current.Reason {
			status = "changed"
		}
		after.Measurements = append(after.Measurements, diag.Measurement{ID: fmt.Sprintf("compare-%d", len(after.Measurements)), Kind: "comparison", Target: old.Target, Status: status, Data: map[string]any{"kind": old.Kind, "before": old.Status, "after": current.Status, "before_reason": old.Reason, "after_reason": current.Reason, "before_mode": before.Mode, "after_mode": after.Mode, "before_at": before.Started, "after_at": after.Started, "before_values": comparisonValues(old), "after_values": comparisonValues(current), "same_targets": true, "vpn_routing_proven": false}})
	}
}

func printCoverage(w io.Writer, values []diag.Measurement) {
	labels := map[string]string{"dns_system": "Системный DNS", "dns_alternative": "Альтернативные DNS", "ip_family": "IPv4/IPv6", "protocol": "HTTP-протоколы", "tls_version": "Версии TLS", "wifi": "Wi-Fi", "traceroute": "Трассировка", "node": "Измерительный узел", "solution_trial": "Испытания DNS", "transport_solution": "Испытания протоколов", "rate_limit_trial": "Испытания ограничения скорости"}
	totals := map[string]map[string]int{}
	for _, m := range values {
		label, ok := labels[m.Kind]
		if !ok {
			continue
		}
		if totals[label] == nil {
			totals[label] = map[string]int{}
		}
		totals[label][m.Status]++
	}
	names := make([]string, 0, len(totals))
	for label := range totals {
		names = append(names, label)
	}
	sort.Strings(names)
	for _, label := range names {
		statuses := make([]string, 0, len(totals[label]))
		for status := range totals[label] {
			statuses = append(statuses, status)
		}
		sort.Strings(statuses)
		parts := []string{}
		for _, status := range statuses {
			parts = append(parts, fmt.Sprintf("%s: %d", statusName(status), totals[label][status]))
		}
		fmt.Fprintf(w, "%s — %s\n", label, strings.Join(parts, "; "))
	}
}
