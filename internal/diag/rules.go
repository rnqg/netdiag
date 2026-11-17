package diag

import (
	"fmt"
	"sort"
)

func Analyze(r Report) []Finding {
	f := []Finding{}
	if r.Command == "quality" {
		received := 0
		var evidence []string
		for _, m := range r.Measurements {
			if m.Kind == "udp_rtt" || m.Kind == "icmp_rtt" {
				evidence = append(evidence, m.ID)
				if m.Stats != nil {
					received += m.Stats.Received
				}
			}
		}
		if received == 0 {
			f = append(f, Finding{Code: "quality_not_measured", Severity: "error", Confidence: "observed", Summary: "Качество соединения не измерено", Evidence: evidence, Next: "Нет успешных RTT-проб. Проверьте доступность измерительного узла и причины отказов; это не доказывает отсутствие интернета."})
		}
	}
	dnsFailures := map[string][]string{}

	if r.Command == "speed" {
		missingLoad := false
		for _, m := range r.Measurements {
			if m.Kind == "bufferbloat" && m.Status != "ok" {
				missingLoad = true
			}
		}
		if missingLoad {
			f = append(f, Finding{Code: "bufferbloat_not_measured", Severity: "info", Confidence: "observed", Summary: "Не все проверки задержки под нагрузкой выполнены", Next: "Для полного теста нужен свой --node, достаточный лимит трафика и ответы на UDP-пробы. Причины пропуска сохранены в измерениях."})
		}
		measured := false
		for _, m := range r.Measurements {
			if (m.Kind == "throughput" || m.Kind == "ndt7") && (m.Status == "ok" || m.Status == "limited") && (number(m.Data["mbps"]) > 0 || number(m.Data["download_mbps"]) > 0 || number(m.Data["upload_mbps"]) > 0) {
				measured = true
			}
		}
		if !measured {
			f = append(f, Finding{Code: "speed_not_measured", Severity: "error", Confidence: "observed", Summary: "Измерение скорости не состоялось", Next: "Проверьте доступность измерительного узла и условия запуска. Этот результат не доказывает отсутствие интернета."})
		}
	}
	if r.NetworkChanged {
		f = append(f, Finding{Code: "network_changed", Severity: "warning", Confidence: "observed", Summary: "Во время проверки изменилось подключение", Next: "Повторите проверку после стабилизации сети. Общие показатели качества этого запуска не сравниваются."})
	}
	if r.Environment.ProxyHint {
		f = append(f, Finding{Code: "proxy_scope", Severity: "info", Confidence: "observed", Summary: "Обнаружены признаки прокси", Next: "Утилита использует прямые соединения по маршрутам ОС. Результаты могут отличаться от браузера и VPN в режиме системного прокси."})
	}
	baselines, reachable := 0, 0
	for _, m := range r.Measurements {
		if m.Kind == "dns_alternative" && m.Status != "ok" && m.Reason != "dns_nodata" {
			key := fmt.Sprintf("%v / %v", m.Data["resolver"], m.Data["method"])
			if family, ok := m.Data["resolver_family"]; ok {
				key += fmt.Sprint(" / ", family)
			}
			dnsFailures[key] = append(dnsFailures[key], m.ID)
		}
		if m.Kind == "path_mtu" && m.Status == "ok" && m.Data["large_packets_failed"] == true {
			f = append(f, Finding{Code: "packet_size_difference", Severity: "warning", Confidence: "observed", Summary: "Результаты UDP-проб зависят от размера пакета", Evidence: []string{m.ID}, Next: "Повторите чередующиеся проверки малых и больших пакетов. Проверьте MTU туннеля и PMTU; точное значение MTU и причина отказа этим замером не установлены."})
		}
		if m.Kind == "transport_solution" && m.Status == "ok" {
			f = append(f, Finding{Code: "transport_alternative_worked", Severity: "warning", Confidence: "tested_workaround", Summary: fmt.Sprintf("На той же цели %v работает, %v не проходит проверку", m.Data["working_protocol"], m.Data["failed_protocol"]), Evidence: []string{m.ID}, Next: "Если приложение позволяет выбирать протокол, повторите с рабочим вариантом. Эти испытания не устанавливают причину отказа и не доказывают блокировку всего протокола."})
		}
		if m.Kind == "http_baseline" {
			baselines++
			if m.Status == "ok" || m.Status == "restricted" {
				reachable++
			}
			if m.Status == "failed" {
				f = append(f, Finding{Code: "target_failed", Severity: "error", Confidence: "observed", Summary: "Не удалось получить ответ: " + m.Target, Evidence: []string{m.ID}, Next: "Этап: " + fmt.Sprint(m.Data["failure_stage"]) + "; результат: " + m.Reason + ". Сам по себе этот сбой не определяет виновника."})
			}
			if m.Status == "restricted" {
				f = append(f, Finding{Code: "http_restricted", Severity: "warning", Confidence: "observed", Summary: "Сервер ответил, но ограничил запрос: " + m.Target, Evidence: []string{m.ID}, Next: "Откройте сайт в браузере: может требоваться авторизация или проверка. Это не подтверждение отсутствия интернета."})
			}
		}
		if m.Kind == "solution_trial" && m.Status == "ok" {
			next := "Вариант с другим DNS сработал в трёх чередующихся испытаниях. Различия адресов CDN тоже могут влиять на результат."
			fix := ""
			if eligible, _ := m.Data["automatic_eligible"].(bool); eligible {
				fix = "dns"
				next = "Проверена смена DNS на " + fmt.Sprint(m.Data["resolver_ip"]) + ". Доступны инструкция и автоматическое исправление с подтверждением и откатом."
			}
			f = append(f, Finding{Code: "dns_alternative_worked", Severity: "warning", Confidence: "tested_workaround", Summary: "Найден рабочий вариант для " + m.Target, Evidence: []string{m.ID}, Next: next, FixID: fix})
		}
		if m.Stats != nil && m.Stats.Sent > 0 {
			if m.Stats.Received == 0 {
				f = append(f, Finding{Code: "probe_no_replies", Severity: "info", Confidence: "observed", Summary: "Нет ответов на пробы " + m.Kind, Evidence: []string{m.ID}, Next: "Узел или сеть могут не отвечать на этот тип проб. Проверяйте вместе с TCP/HTTPS; потеря всех проб не доказывает потерю всего трафика."})
			} else if m.Stats.LossPercent > 0 {
				f = append(f, Finding{Code: "probe_loss", Severity: "warning", Confidence: "observed", Summary: fmt.Sprintf("%s: %.1f%% проб без своевременного ответа", m.Kind, m.Stats.LossPercent), Evidence: []string{m.ID}, Next: "Сравните шлюз и внешний узел; повторите без нагрузки и, для Wi-Fi, по кабелю. По этому замеру нельзя однозначно определить место потерь."})
			}
		}
		if m.Kind == "bufferbloat" && m.Status == "ok" {
			delta := number(m.Data["p95_increase_ms"])
			if delta >= 20 {
				f = append(f, Finding{Code: "loaded_latency", Severity: "warning", Confidence: "observed", Summary: fmt.Sprintf("Под нагрузкой %v p95 RTT вырос на %.1f мс", m.Data["phase"], delta), Evidence: []string{m.ID}, Next: "Сравните повтор с ограничением нагрузки. Для устойчивого улучшения проверьте SQM/CAKE/fq_codel на роутере; поддержка зависит от оборудования."})
			}
		}
		if m.Kind == "rate_limit_trial" && m.Status == "ok" {
			f = append(f, Finding{Code: "rate_limit_helped", Severity: "warning", Confidence: "tested_workaround", Summary: "Ограничение тестовой нагрузки уменьшило задержку", Evidence: []string{m.ID}, Next: "В этом испытании помогло ограничение нагрузки. Проверьте ограничение скорости или SQM на роутере; постоянная конфигурация утилитой не изменялась."})
		}
		if m.Kind == "http_baseline" && (m.Reason == "tls_certificate_invalid" || m.Reason == "tls_unknown_authority" || m.Reason == "tls_hostname") {
			f = append(f, Finding{Code: "tls_validation", Severity: "warning", Confidence: "observed", Summary: "Не прошла проверка сертификата: " + m.Target, Evidence: []string{m.ID}, Next: "Проверьте дату и время, сертификат сервиса и наличие HTTPS-фильтрации. Не отключайте проверку сертификата как исправление."})
		}
		if m.Kind == "wifi" && m.Status == "ok" {
			if rssi, ok := m.Data["rssi_dbm"]; ok && number(rssi) < -75 {
				f = append(f, Finding{Code: "wifi_signal", Severity: "warning", Confidence: "observed", Summary: "Во время замера сигнал Wi-Fi был слабым", Evidence: []string{m.ID}, Next: "Повторите проверку ближе к точке доступа или по кабелю. Одного значения сигнала недостаточно, чтобы объяснить все сетевые ошибки."})
			}
		}
	}
	keys := make([]string, 0, len(dnsFailures))
	for key := range dnsFailures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		f = append(f, Finding{Code: "dns_transport_failed", Severity: "info", Confidence: "observed", Summary: "Не все DNS-пробы успешны: " + key, Evidence: dnsFailures[key], Next: "Смотрите причины отдельных проб. Отказ этого DNS-транспорта не означает отказ системного DNS или всего подключения."})
	}
	if baselines > 0 && reachable == 0 {
		f = append(f, Finding{Code: "all_targets_failed", Severity: "error", Confidence: "observed", Summary: "Ни одна выбранная веб-цель не ответила", Next: "Проверьте подключение и шлюз. Если другие приложения работают, сравните их прокси, DNS и маршрутизацию с утилитой."})
	}
	for _, target := range r.Targets {
		var v4, v6 *Measurement
		for i := range r.Measurements {
			m := &r.Measurements[i]
			if m.Target == target.URL && m.Kind == "ip_family" {
				if m.Data["family"] == "ipv4" {
					v4 = m
				} else {
					v6 = m
				}
			}
		}
		if v4 != nil && v6 != nil && v4.Status == "ok" && v6.Status == "failed" {
			f = append(f, Finding{Code: "ipv6_difference", Severity: "warning", Confidence: "observed", Summary: "IPv4 работает, IPv6 не прошёл проверку: " + target.Name, Evidence: []string{v4.ID, v6.ID}, Next: "Повторите на другой цели. Проверьте IPv6-маршрут и настройки VPN; не отключайте IPv6 глобально по одному результату."})
		}
	}
	if r.Partial {
		f = append(f, Finding{Code: "partial", Severity: "info", Confidence: "observed", Summary: "Проверка завершена частично", Next: "Смотрите причины пропущенных измерений; при необходимости повторите с большим временем."})
	}
	return f
}

func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
