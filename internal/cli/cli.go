package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"netdiag/internal/diag"
	"netdiag/internal/fix"

	"golang.org/x/term"
)

const help = `netdiag — диагностика сети

  netdiag
  netdiag check --mode direct --profile deep --output report.json
  netdiag check --mode vpn --target example.org --verbose
  netdiag quality --mode direct --duration 60s
  netdiag speed --mode direct --node https://node.example.org:8443
  netdiag speed --mode direct --accept-mlab-policy
  netdiag compare --baseline report.json --mode vpn
  netdiag report --input report.json --verbose
  netdiag fix --input report.json
  netdiag fix --input report.json --apply

Параметры:
  --mode direct|vpn       Подтверждённый пользователем режим
  --profile quick|deep    Глубина проверки, по умолчанию deep
  --target домен          Добавить цель; путь, пароль и параметры URL не используются
  --only-target           Проверять только указанные цели
  --duration 60s          Продолжительность замера качества (2s..5m)
  --node HTTPS-origin     Свой измерительный узел
  --token-env имя         Имя переменной с токеном узла, по умолчанию NETDIAG_NODE_TOKEN
  --max-mib 1024          Предел тестовых данных; служебный трафик дополнительно
  --accept-mlab-policy    Согласие на публичные результаты и внешний IP в M-Lab
  --trace                Добавить ограниченную трассировку
  --format text|json      Формат stdout
  --output путь           Сохранить JSON без перезаписи существующего файла
  --verbose              Подробные измерения

Коды выхода: 0 — завершено, 1 — обнаружена ошибка, 2 — ошибка запуска, 3 — частично.
По умолчанию файлы не создаются. M-Lab и изменение настроек автоматически не запускаются.
`

type targetsFlag []string

func (t *targetsFlag) String() string     { return strings.Join(*t, ",") }
func (t *targetsFlag) Set(s string) error { *t = append(*t, s); return nil }

func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, interactive bool) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprint(out, help)
		return 0
	}
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(out, diag.Version)
		return 0
	}
	reader := bufio.NewReader(in)
	ask := func(prompt, defaultValue string) string {
		fmt.Fprint(errOut, prompt)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return defaultValue
		}
		return line
	}
	command := "check"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	} else if !interactive {
		fmt.Fprint(errOut, help)
		return 2
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	mode := fs.String("mode", "auto", "")
	profile := fs.String("profile", "deep", "")
	duration := fs.Duration("duration", 60*time.Second, "")
	nodeURL := fs.String("node", "", "")
	tokenEnv := fs.String("token-env", "NETDIAG_NODE_TOKEN", "")
	maxMiB := fs.Int64("max-mib", 1024, "")
	consent := fs.Bool("accept-mlab-policy", false, "")
	trace := fs.Bool("trace", false, "")
	format := fs.String("format", "text", "")
	output := fs.String("output", "", "")
	verbose := fs.Bool("verbose", false, "")
	input := fs.String("input", "", "")
	baseline := fs.String("baseline", "", "")
	apply := fs.Bool("apply", false, "")
	flush := fs.Bool("flush-cache", false, "")
	recoverPath := fs.String("recover", "", "")
	only := fs.Bool("only-target", false, "")
	var targetArgs targetsFlag
	fs.Var(&targetArgs, "target", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, help)
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "Неожиданные аргументы; используйте --help.")
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(errOut, "Формат: text или json.")
		return 2
	}
	if command == "report" {
		r, err := ReadReport(*input)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		return emit(out, errOut, r, *format, *output, *verbose)
	}
	if command == "fix" {
		if *recoverPath != "" {
			if !interactive {
				fmt.Fprintln(errOut, "Восстановление требует интерактивного подтверждения.")
				return 2
			}
			if ask("Восстановить настройки из сохранённого снимка? Введите да: ", "") != "да" {
				return 0
			}
			if err := fix.Resume(ctx, *recoverPath); err != nil {
				fmt.Fprintln(errOut, err)
				return 1
			}
			fmt.Fprintln(out, "Исходные настройки восстановлены.")
			return 0
		}
		var plan fix.Plan
		var err error
		if *flush {
			plan = fix.Plan{Action: "flush"}
		} else {
			var r diag.Report
			r, err = ReadReport(*input)
			if err == nil {
				if *apply {
					plan, err = fix.PlanFromReport(r)
				} else {
					plan, err = fix.Candidate(r)
				}
			}
		}
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		fmt.Fprintln(out, fix.Instructions(plan))
		if !*apply {
			return 0
		}
		if !interactive {
			fmt.Fprintln(errOut, "Автоисправление доступно только с интерактивным подтверждением.")
			return 2
		}
		if plan.Action == "dns" {
			readCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			original, readErr := (fix.SystemAdapter{}).Read(readCtx, plan.Interface)
			stop()
			if readErr != nil {
				fmt.Fprintln(errOut, readErr)
				return 2
			}
			plan.Expected = original
			plan.HasExpected = true
			if original.Automatic {
				fmt.Fprintln(errOut, "Исходный DNS: автоматически.")
			} else {
				fmt.Fprintln(errOut, "Исходный DNS:", strings.Join(original.DNS, ", "))
			}
		}
		fmt.Fprintf(errOut, "Изменение: %s; интерфейс: %s; DNS: %s. Понадобятся права администратора.\n", plan.Action, plan.Interface, plan.Resolver)
		if ask("Применить? Введите да: ", "") != "да" {
			fmt.Fprintln(out, "Изменения не выполнялись.")
			return 0
		}
		if err = fix.Launch(ctx, plan); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	}
	if command != "check" && command != "quality" && command != "speed" && command != "compare" {
		fmt.Fprintln(errOut, "Неизвестная команда. Используйте --help.")
		return 2
	}
	if *duration < 2*time.Second || *duration > 5*time.Minute || *maxMiB < 1 || *maxMiB > 16384 || (*profile != "quick" && *profile != "deep") {
		fmt.Fprintln(errOut, "Некорректная длительность, профиль или предел трафика.")
		return 2
	}
	if *mode == "auto" {
		if !interactive {
			fmt.Fprintln(errOut, "Укажите --mode direct или --mode vpn; автоопределение не подтверждает маршрутизацию.")
			return 2
		}
		suggestion := "direct"
		if diag.Inspect().VPNHint {
			suggestion = "vpn"
			fmt.Fprintln(errOut, "Есть интерфейсы, похожие на VPN. Это предположение.")
		}
		*mode = ask("Режим direct (без VPN) или vpn ["+suggestion+"]: ", suggestion)
	}
	if *mode != "direct" && *mode != "vpn" {
		fmt.Fprintln(errOut, "Режим: direct или vpn.")
		return 2
	}
	selected := diag.Catalog(*mode)
	if *only {
		selected = nil
	}
	for _, arg := range targetArgs {
		target, err := diag.NormalizeTarget(arg)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		selected = append(selected, target)
	}
	if len(selected) == 0 || len(selected) > 16 {
		fmt.Fprintln(errOut, "Нужно от 1 до 16 целей.")
		return 2
	}
	if *nodeURL != "" && os.Getenv(*tokenEnv) == "" {
		fmt.Fprintln(errOut, "Задайте токен узла в переменной "+*tokenEnv+".")
		return 2
	}
	if command == "speed" && *nodeURL == "" && !*consent {
		fmt.Fprintln(errOut, "M-Lab публикует результаты и внешний IP: https://www.measurementlab.net/privacy/")
		if !interactive || ask("Запустить тест на этих условиях? Введите да: ", "") != "да" {
			fmt.Fprintln(errOut, "Тест не запущен. Для своего сервера используйте --node.")
			return 2
		}
		*consent = true
	}
	if command == "speed" && interactive {
		if ask(fmt.Sprintf("Нагрузочный тест: до %d МиБ тестовых данных и служебный трафик. Продолжить? да: ", *maxMiB), "") != "да" {
			return 0
		}
	}
	opts := diag.Options{Mode: *mode, Profile: *profile, Targets: selected, Duration: *duration, Node: *nodeURL, NodeToken: os.Getenv(*tokenEnv), AcceptMLab: *consent, MaxBytes: *maxMiB << 20, Traceroute: *trace}
	if interactive {
		var progressMu sync.Mutex
		opts.Progress = func(s string) {
			progressMu.Lock()
			defer progressMu.Unlock()
			fmt.Fprintln(errOut, "Проверяется:", s)
		}
	}
	var r diag.Report
	run, cancel := context.WithCancel(ctx)
	stopMonitor := diag.MonitorNetwork(run, cancel)
	defer stopMonitor()
	defer cancel()
	ctx = run
	switch command {
	case "check":
		r = diag.RunCheck(ctx, opts)
	case "quality":
		r = diag.RunQuality(ctx, opts)
	case "speed":
		if opts.Node != "" {
			r = diag.RunNodeSpeed(ctx, opts)
		} else {
			r = diag.RunMLab(ctx, opts)
		}
	case "compare":
		previous, err := ReadReport(*baseline)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		if previous.Command != "check" {
			fmt.Fprintln(errOut, "Сравнение ожидает отчёт check.")
			return 2
		}
		opts.Targets = nil
		for _, t := range previous.Targets {
			normalized, err := diag.NormalizeTarget(t.URL)
			if err != nil {
				fmt.Fprintln(errOut, "Некорректная цель в отчёте.")
				return 2
			}
			normalized.Name = t.Name
			opts.Targets = append(opts.Targets, normalized)
		}
		if len(opts.Targets) == 0 {
			fmt.Fprintln(errOut, "В отчёте нет целей.")
			return 2
		}
		opts.Profile = previous.Profile
		r = diag.RunCheck(ctx, opts)
		Compare(previous, &r)
	}
	if stopMonitor() {
		r.NetworkChanged = true
		r.Partial = true
		r.Findings = diag.Analyze(r)
	}
	return emit(out, errOut, r, *format, *output, *verbose)
}

func emit(out, errOut io.Writer, r diag.Report, format, output string, verbose bool) int {
	if output != "" {
		if err := WriteReport(output, r); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return 2
		}
	} else {
		PrintReport(out, r, verbose)
	}
	if r.Partial {
		return 3
	}
	for _, f := range r.Findings {
		if f.Severity == "error" {
			return 1
		}
	}
	return 0
}

func Interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}
