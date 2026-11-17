package fix

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"netdiag/internal/diag"

	"github.com/miekg/dns"
)

type Plan struct {
	Action, Interface, Resolver, Target, Fingerprint, Method string
	Expected                                                 State
	HasExpected                                              bool
}
type Record struct {
	Format   string    `json:"format"`
	OwnerPID int       `json:"owner_pid"`
	Created  time.Time `json:"created"`
	Plan     Plan      `json:"plan"`
	Nonce    string    `json:"nonce"`
	Before   State     `json:"before"`
	Written  State     `json:"written"`
	Prepared bool      `json:"prepared"`
	Finished bool      `json:"finished"`
	Kept     bool      `json:"kept"`
	Restored bool      `json:"restored"`
	Failure  string    `json:"failure,omitempty"`
	Deadline time.Time `json:"deadline"`
}

func Instructions(p Plan) string {
	if p.Action == "flush" {
		return "Очистите кэш DNS средствами вашей ОС, затем повторите исходную проверку. Очистка кэша не меняет конфигурацию подключения."
	}
	if p.Method == "doh" || p.Method == "dot" {
		address := p.Resolver
		for _, resolver := range diag.Resolvers {
			if resolver.IP == p.Resolver {
				if p.Method == "doh" {
					address = resolver.DoH
				} else {
					address = resolver.DoT
				}
			}
		}
		return "В испытаниях сработал защищённый DNS " + p.Method + ": " + address + ". Укажите его в используемом приложении или VPN-клиенте и повторите проверку. Простая замена IP системного DNS не воспроизводит этот вариант."
	}
	return "Откройте настройки DNS активного подключения, сохраните исходные значения и режим DHCP, укажите проверенный DNS " + p.Resolver + ", затем повторите проверку проблемного сайта и контрольных целей. Если результат ухудшился — восстановите исходные значения. Не меняйте настройки VPN-клиента или управляемого рабочего подключения."
}

func Candidate(r diag.Report) (Plan, error) {
	for _, m := range r.Measurements {
		if m.Kind != "solution_trial" || m.Status != "ok" {
			continue
		}
		ip, _ := m.Data["resolver_ip"].(string)
		method, _ := m.Data["dns_method"].(string)
		for _, known := range diag.Resolvers {
			if known.IP != ip {
				continue
			}
			target, err := diag.NormalizeTarget(m.Target)
			if err != nil {
				return Plan{}, err
			}
			return Plan{Action: "dns", Resolver: ip, Method: method, Target: target.URL}, nil
		}
	}
	return Plan{}, errors.New("в отчёте нет подтверждённого рабочего DNS-варианта")
}

func PlanFromReport(r diag.Report) (Plan, error) {
	if r.NetworkChanged || r.Partial {
		return Plan{}, errors.New("для автоисправления нужна полная проверка в неизменившейся сети")
	}
	if time.Since(r.Finished) > 15*time.Minute || r.Finished.After(time.Now().Add(time.Minute)) {
		return Plan{}, errors.New("отчёт устарел; повторите диагностику")
	}
	e := diag.Inspect()
	if e.VPNHint || e.ProxyHint {
		return Plan{}, errors.New("обнаружен VPN или прокси; используйте инструкцию, чтобы не перезаписать настройки клиента")
	}
	for _, m := range r.Measurements {
		if m.Kind == "solution_trial" && m.Status == "ok" && m.Data["automatic_eligible"] == true {
			ip, _ := m.Data["resolver_ip"].(string)
			known := false
			for _, v := range diag.Resolvers {
				known = known || v.IP == ip
			}
			if !known {
				continue
			}
			target, err := diag.NormalizeTarget(m.Target)
			if err != nil {
				return Plan{}, err
			}
			return Plan{Action: "dns", Interface: e.ActiveInterface, Resolver: ip, Target: target.URL, Fingerprint: e.Fingerprint}, nil
		}
	}
	return Plan{}, errors.New("нет подтверждённого DNS-решения для автоматического применения")
}

func save(path string, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "state-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func load(path, nonce string) (Record, error) {
	var r Record
	if filepath.Base(path) != "state.json" || !strings.HasPrefix(filepath.Base(filepath.Dir(path)), "net-repair-") {
		return r, errors.New("invalid recovery path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return r, err
	}
	if !info.Mode().IsRegular() {
		return r, errors.New("invalid recovery file")
	}
	dirInfo, dirErr := os.Lstat(filepath.Dir(path))
	if dirErr != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return r, errors.New("invalid recovery directory")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if len(b) > 32768 {
		return r, errors.New("invalid recovery size")
	}
	if json.Unmarshal(b, &r) != nil || r.Nonce != nonce || r.Format != "netdiag-recovery-v1" {
		return r, errors.New("invalid recovery record")
	}
	return r, nil
}

func Launch(ctx context.Context, p Plan) error {
	if p.Action != "dns" && p.Action != "flush" {
		return errors.New("unsupported fix")
	}
	dir, err := os.MkdirTemp("", "net-repair-")
	if err != nil {
		return err
	}
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "state.json")
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		os.RemoveAll(dir)
		return err
	}
	nonce := hex.EncodeToString(token)
	r := Record{Plan: p, Nonce: nonce, Format: "netdiag-recovery-v1", OwnerPID: os.Getpid(), Created: time.Now().UTC()}
	if err = save(path, r); err != nil {
		os.RemoveAll(dir)
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		os.RemoveAll(dir)
		return err
	}
	err = elevate(ctx, executable, []string{"_apply", path, nonce})
	result, readErr := load(path, nonce)
	if readErr == nil && (!result.Prepared || result.Finished && result.Failure == "") {
		os.RemoveAll(dir)
	}
	if readErr == nil && result.Finished && result.Failure != "" {
		return fmt.Errorf("%s; состояние восстановления: %s", result.Failure, path)
	}
	if err != nil && readErr == nil && !result.Prepared {
		os.RemoveAll(dir)
		return fmt.Errorf("исправление не запущено: %w", err)
	}
	if readErr != nil {
		return fmt.Errorf("не удалось прочитать результат исправления: %w", readErr)
	}
	if !result.Finished {
		return fmt.Errorf("исправление не завершено; независимый процесс восстановит настройки. Снимок: %s", path)
	}
	if result.Restored {
		fmt.Fprintln(os.Stdout, "Исходные настройки восстановлены.")
	} else if result.Kept {
		fmt.Fprintln(os.Stdout, "Исправление применено и проверено.")
	}
	return err
}

func ApplyWorker(ctx context.Context, path, nonce string) error {
	r, err := load(path, nonce)
	if err != nil {
		return err
	}
	if !isElevated() {
		return errors.New("для изменения настроек нужны права администратора")
	}
	defer func() {
		if !r.Prepared {
			r.Finished = true
		}
		save(path, r)
	}()
	if r.Plan.Action == "flush" {
		err = Flush(ctx)
		r.Finished = true
		if err != nil {
			r.Failure = "не удалось очистить кэш DNS"
		} else {
			fmt.Fprintln(os.Stdout, "Кэш DNS очищен. Повторите исходную проверку, чтобы проверить результат.")
		}
		return err
	}
	e := diag.Inspect()
	if e.Fingerprint != r.Plan.Fingerprint || e.VPNHint || e.ProxyHint {
		return errors.New("состояние подключения изменилось; повторите диагностику")
	}
	known := false
	var resolver diag.Resolver
	for _, candidate := range diag.Resolvers {
		if candidate.IP == r.Plan.Resolver {
			known = true
			resolver = candidate
		}
	}
	if !known {
		return errors.New("неизвестный DNS")
	}
	target, err := diag.NormalizeTarget(r.Plan.Target)
	if err != nil {
		return err
	}
	host, _ := neturlHost(target.URL)
	fresh, stop := context.WithTimeout(ctx, 100*time.Second)
	defer stop()
	for i := 0; i < 3; i++ {
		base := diag.Probe(fresh, target, diag.ProbeConfig{})
		if base.Reason != "dns_not_found" && base.Reason != "dns_timeout" && base.Reason != "dns_error" {
			return errors.New("повторная проверка не подтверждает исходную ошибку DNS")
		}
		_, ips := diag.QueryDNS(fresh, host, resolver, "udp", dns.TypeA)
		if len(ips) == 0 {
			return errors.New("предлагаемый DNS больше не отвечает")
		}
		alt := diag.Probe(fresh, target, diag.ProbeConfig{Addresses: ips})
		if alt.Status != "ok" {
			return errors.New("предлагаемый DNS не подтвердил исправление")
		}
	}
	controls := []diag.Target{{Name: "Яндекс", URL: "https://ya.ru/"}, {Name: "Mail", URL: "https://mail.ru/"}}
	for _, control := range controls {
		h, _ := neturlHost(control.URL)
		_, ips := diag.QueryDNS(fresh, h, resolver, "udp", dns.TypeA)
		if len(ips) == 0 || diag.Probe(fresh, control, diag.ProbeConfig{Addresses: ips}).Status != "ok" {
			return errors.New("предлагаемый DNS не прошёл контрольные проверки")
		}
	}
	adapter := SystemAdapter{}
	before, err := adapter.Read(ctx, r.Plan.Interface)
	if err != nil {
		return err
	}
	if r.Plan.HasExpected && !Same(before, r.Plan.Expected) {
		return errors.New("настройки изменились после подтверждения; повторите проверку")
	}
	desired := Desired(before, r.Plan.Resolver)
	run, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	kept, err := Transact(run, adapter, before, desired, TransactionHooks{
		Prepared: func(a, b State) error {
			r.Plan.Expected = State{}
			r.Plan.HasExpected = false
			r.Before = a
			r.Written = b
			r.Prepared = true
			r.Deadline = time.Now().Add(125 * time.Second)
			if err := save(path, r); err != nil {
				return err
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			guard := exec.Command(exe, "_restore-watch", path, nonce)
			detach(guard)
			if err = guard.Start(); err != nil {
				return err
			}
			return guard.Process.Release()
		},
		Verify: func(c context.Context) error {
			Flush(c)
			for _, t := range append([]diag.Target{target}, controls...) {
				for i := 0; i < 2; i++ {
					if diag.Probe(c, t, diag.ProbeConfig{}).Status != "ok" {
						return errors.New("после изменения проверка не прошла")
					}
				}
			}
			return nil
		},
		Keep: func(c context.Context) bool {
			fmt.Fprintln(os.Stdout, "Проверки прошли. Оставить DNS? Введите да в течение 30 секунд; иначе настройки будут восстановлены.")
			answer := make(chan string, 1)
			go func() { line, _ := bufio.NewReader(os.Stdin).ReadString('\n'); answer <- strings.TrimSpace(line) }()
			select {
			case line := <-answer:
				return (line == "да" || strings.EqualFold(line, "yes")) && c.Err() == nil
			case <-time.After(30 * time.Second):
				return false
			case <-c.Done():
				return false
			}
		},
	})
	r.Finished = true
	r.Kept = kept
	if !kept {
		rollback, checkErr := adapter.Read(context.Background(), before.Interface)
		r.Restored = checkErr == nil && Same(rollback, before)
	}
	if err != nil && !r.Restored {
		r.Failure = err.Error()
	}
	if err != nil && r.Restored {
		fmt.Fprintln(os.Stdout, "Исправление не прошло проверку; исходные настройки восстановлены.")
	}
	return save(path, r)
}

func Guard(ctx context.Context, path, nonce string) error {
	ignoreInterrupts()
	for ctx.Err() == nil {
		r, err := load(path, nonce)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.Finished {
			if r.Failure == "" {
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Second):
				}
				os.RemoveAll(filepath.Dir(path))
			}
			return nil
		}
		if r.Prepared && time.Now().After(r.Deadline) {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := Restore(restoreCtx, SystemAdapter{}, r.Before, r.Written)
			cancel()
			r.Finished = true
			r.Restored = err == nil
			if err != nil {
				r.Failure = err.Error()
			}
			save(path, r)
			if err == nil {
				os.RemoveAll(filepath.Dir(path))
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return ctx.Err()
}

func neturlHost(value string) (string, error) {
	t, err := diag.NormalizeTarget(value)
	if err != nil {
		return "", err
	}
	host := strings.TrimPrefix(strings.TrimPrefix(t.URL, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	return strings.Trim(host, "[]"), nil
}

func Recoveries() []string {
	paths, _ := filepath.Glob(filepath.Join(os.TempDir(), "net-repair-*", "state.json"))
	result := []string{}
	for _, path := range paths {
		if !ownedDirectory(filepath.Dir(path)) {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var r Record
		err = json.NewDecoder(io.LimitReader(f, 32768)).Decode(&r)
		f.Close()
		if err != nil || r.Format != "netdiag-recovery-v1" {
			continue
		}
		if processAlive(r.OwnerPID) && r.Failure == "" && (!r.Prepared || r.Finished || r.Deadline.After(time.Now())) || r.Prepared && !r.Finished && r.Deadline.After(time.Now()) {
			continue
		}
		if !r.Prepared || r.Finished && r.Failure == "" {
			os.RemoveAll(filepath.Dir(path))
			continue
		}
		result = append(result, path)
	}
	return result
}

func Resume(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var r Record
	err = json.NewDecoder(io.LimitReader(f, 32768)).Decode(&r)
	f.Close()
	if err != nil {
		return err
	}
	if _, err = load(path, r.Nonce); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	err = elevate(ctx, exe, []string{"_recover", path, r.Nonce})
	if err != nil {
		return err
	}
	r, err = load(path, r.Nonce)
	if err != nil {
		return err
	}
	if !r.Restored || r.Failure != "" {
		return fmt.Errorf("восстановление не подтверждено; снимок: %s", path)
	}
	return os.RemoveAll(filepath.Dir(path))
}

func RecoverWorker(ctx context.Context, path, nonce string) error {
	if !isElevated() {
		return errors.New("нужны права администратора")
	}
	r, err := load(path, nonce)
	if err != nil {
		return err
	}
	if !r.Prepared {
		return errors.New("в снимке нет исходных настроек")
	}
	run, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = Restore(run, SystemAdapter{}, r.Before, r.Written)
	if err != nil {
		r.Failure = err.Error()
		save(path, r)
		return err
	}
	r.Finished = true
	r.Restored = true
	r.Kept = false
	r.Failure = ""
	return save(path, r)
}
