package cli

import (
	"errors"
	"fmt"
	"io"

	"netdiag/internal/diag"
)

func flushVerificationTarget(input string, args []string) (string, error) {
	var selected string
	switch {
	case len(args) > 1 || len(args) > 0 && input != "":
		return "", errors.New("для очистки кэша укажите один --target или один --input")
	case len(args) == 1:
		selected = args[0]
	case input != "":
		r, err := ReadReport(input)
		if err != nil {
			return "", err
		}
		for _, m := range r.Measurements {
			if m.Kind == "http_baseline" && (m.Reason == "dns_not_found" || m.Reason == "dns_timeout" || m.Reason == "dns_error") {
				selected = m.Target
				break
			}
		}
		if selected == "" && len(r.Targets) > 0 {
			selected = r.Targets[0].URL
		}
		if selected == "" {
			return "", errors.New("в отчёте нет цели для повторной проверки")
		}
	default:
		return "", nil
	}
	target, err := diag.NormalizeTarget(selected)
	return target.URL, err
}

func printFlushVerification(w io.Writer, target string, before, after diag.Measurement) int {
	w = terminalWriter{w}
	fmt.Fprintf(w, "%s\nДо очистки: %s\nПосле очистки: %s\n", target, flushProbeResult(before), flushProbeResult(after))
	if after.Status != "ok" {
		return 1
	}
	return 0
}

func flushProbeResult(m diag.Measurement) string {
	if m.Reason == "" {
		return statusName(m.Status)
	}
	return statusName(m.Status) + " (" + m.Reason + ")"
}
