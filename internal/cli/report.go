package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
		if r < 32 && r != '\n' && r != '\t' || r == 127 || r == 0x202e || r == 0x202d {
			return -1
		}
		return r
	}, s)
}

func PrintReport(w io.Writer, r diag.Report, verbose bool) {
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
		if m.Kind == "comparison" {
			fmt.Fprintf(w, "\n%s: %v → %v\n", clean(m.Target), m.Data["before"], m.Data["after"])
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

func Compare(before diag.Report, after *diag.Report) {
	for _, old := range before.Measurements {
		if old.Kind != "http_baseline" {
			continue
		}
		for _, current := range after.Measurements {
			if current.Kind == "http_baseline" && current.Target == old.Target {
				status := "ok"
				if old.Status != current.Status {
					status = "changed"
				}
				after.Measurements = append(after.Measurements, diag.Measurement{ID: "compare-" + current.ID, Kind: "comparison", Target: old.Target, Status: status, Data: map[string]any{"before": old.Status, "after": current.Status, "before_reason": old.Reason, "after_reason": current.Reason, "before_mode": before.Mode, "after_mode": after.Mode, "before_at": before.Started, "after_at": after.Started, "same_targets": true, "vpn_routing_proven": false}})
				break
			}
		}
	}
}
