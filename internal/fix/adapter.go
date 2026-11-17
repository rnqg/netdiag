package fix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netdiag/internal/diag"
)

type State struct {
	Interface string   `json:"interface"`
	Service   string   `json:"service,omitempty"`
	DNS       []string `json:"dns"`
	Automatic bool     `json:"automatic"`
	Values    []string `json:"values,omitempty"`
}

type Adapter interface {
	Read(context.Context, string) (State, error)
	Write(context.Context, State) error
}
type SystemAdapter struct{}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (SystemAdapter) Read(ctx context.Context, iface string) (State, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s := State{Interface: iface, DNS: []string{}}
	if iface == "" {
		return s, errors.New("активный интерфейс не определён")
	}
	switch runtime.GOOS {
	case "darwin":
		managed, e := diag.SystemCommand(ctx, "profiles", "status", "-type", "enrollment")
		if e != nil {
			return s, errors.New("не удалось проверить управление профилями macOS; доступна ручная инструкция")
		}
		if strings.Contains(string(managed), "MDM enrollment: Yes") || strings.Contains(string(managed), "Enrolled via DEP: Yes") {
			return s, errors.New("управляемый Mac: автоматическая смена DNS отключена")
		}
		b, err := diag.SystemCommand(ctx, "networksetup", "-listnetworkserviceorder")
		if err != nil {
			return s, errors.New("не удалось прочитать службы сети")
		}
		service := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "(") && !strings.HasPrefix(line, "(Hardware Port:") {
				if at := strings.Index(line, ") "); at >= 0 {
					service = line[at+2:]
				}
			}
			if strings.Contains(line, "Device: "+iface+")") {
				s.Service = service
				break
			}
		}
		if s.Service == "" {
			return s, errors.New("интерфейс не сопоставлен со службой macOS")
		}
		b, err = diag.SystemCommand(ctx, "networksetup", "-getdnsservers", s.Service)
		if err != nil {
			return s, err
		}
		text := strings.TrimSpace(string(b))
		if strings.HasPrefix(text, "There aren't any DNS Servers set") {
			s.Automatic = true
			return s, nil
		}
		for _, line := range strings.Fields(text) {
			if net.ParseIP(line) == nil {
				return s, errors.New("неизвестный формат DNS macOS")
			}
			s.DNS = append(s.DNS, line)
		}
	case "linux":
		b, err := diag.SystemCommand(ctx, "nmcli", "-g", "GENERAL.CON-UUID", "device", "show", iface)
		if err != nil {
			return s, errors.New("автоисправление Linux требует NetworkManager")
		}
		s.Service = strings.TrimSpace(string(b))
		if s.Service == "" || s.Service == "--" {
			return s, errors.New("нет активного профиля NetworkManager")
		}
		b, err = diag.SystemCommand(ctx, "nmcli", "-g", "ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns", "connection", "show", s.Service)
		if err != nil {
			return s, err
		}
		s.Values = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		if len(s.Values) != 4 {
			return s, errors.New("неизвестный формат NetworkManager")
		}
		for _, index := range []int{0, 2} {
			for _, ip := range strings.Split(s.Values[index], ",") {
				ip = strings.TrimSpace(ip)
				if ip != "" {
					if net.ParseIP(ip) == nil {
						return s, errors.New("неподдерживаемые DNS-настройки NetworkManager")
					}
					s.DNS = append(s.DNS, ip)
				}
			}
		}
		s.Automatic = s.Values[1] == "no" && s.Values[3] == "no" && len(s.DNS) == 0
	case "windows":
		policy, e := diag.SystemCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "if((Test-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient') -or @(Get-DnsClientNrptPolicy -Effective -ErrorAction SilentlyContinue).Count -gt 0){'managed'}else{'unmanaged'}")
		if e != nil || strings.TrimSpace(string(policy)) != "unmanaged" {
			return s, errors.New("DNS управляется политикой или состояние политики не определено; доступна ручная инструкция")
		}
		script := "$a=Get-NetAdapter -Name " + psQuote(iface) + " -ErrorAction Stop; $g=$a.InterfaceGuid.ToString('B'); $v4=(Get-ItemProperty -LiteralPath ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\'+$g) -ErrorAction Stop).NameServer; $v6=(Get-ItemProperty -LiteralPath ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\'+$g) -ErrorAction SilentlyContinue).NameServer; [pscustomobject]@{Index=$a.ifIndex;V4=[string]$v4;V6=[string]$v6}|ConvertTo-Json -Compress"
		b, err := diag.SystemCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		if err != nil {
			return s, errors.New("не удалось прочитать исходную конфигурацию DNS Windows")
		}
		var out struct {
			Index  int
			V4, V6 string
		}
		if json.Unmarshal(b, &out) != nil || out.Index == 0 {
			return s, errors.New("неизвестный формат DNS Windows")
		}
		if out.V6 != "" {
			return s, errors.New("статический IPv6 DNS: автоматическое изменение пока не поддерживается; используйте инструкцию")
		}
		s.Service = strconv.Itoa(out.Index)
		s.Automatic = strings.TrimSpace(out.V4) == ""
		for _, ip := range strings.FieldsFunc(out.V4, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if net.ParseIP(ip) == nil {
				return s, errors.New("неподдерживаемый DNS Windows")
			}
			s.DNS = append(s.DNS, ip)
		}
	default:
		return s, errors.New("нет адаптера исправления для этой ОС")
	}
	return s, nil
}

func (SystemAdapter) Write(ctx context.Context, s State) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, ip := range s.DNS {
		if net.ParseIP(ip) == nil {
			return errors.New("некорректный адрес DNS")
		}
	}
	var err error
	switch runtime.GOOS {
	case "darwin":
		args := []string{"-setdnsservers", s.Service}
		if s.Automatic {
			args = append(args, "Empty")
		} else {
			args = append(args, s.DNS...)
		}
		_, err = diag.SystemCommand(ctx, "networksetup", args...)
	case "linux":
		if len(s.Values) != 4 {
			return errors.New("неполный снимок NetworkManager")
		}
		_, err = diag.SystemCommand(ctx, "nmcli", "connection", "modify", s.Service, "ipv4.dns", s.Values[0], "ipv4.ignore-auto-dns", s.Values[1], "ipv6.dns", s.Values[2], "ipv6.ignore-auto-dns", s.Values[3])
		if err == nil {
			_, err = diag.SystemCommand(ctx, "nmcli", "device", "reapply", s.Interface)
		}
	case "windows":
		index, e := strconv.Atoi(s.Service)
		if e != nil || index < 1 {
			return errors.New("некорректный индекс интерфейса")
		}
		script := "$ErrorActionPreference='Stop'; Set-DnsClientServerAddress -InterfaceIndex " + strconv.Itoa(index)
		if s.Automatic {
			script += " -ResetServerAddresses"
		} else {
			ips := []string{}
			for _, ip := range s.DNS {
				ips = append(ips, psQuote(ip))
			}
			script += " -ServerAddresses @(" + strings.Join(ips, ",") + ")"
		}
		_, err = diag.SystemCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	default:
		err = errors.New("неподдерживаемая ОС")
	}
	if err != nil {
		return fmt.Errorf("изменение DNS не завершилось: %w", err)
	}
	return nil
}

func Desired(old State, ip string) State {
	s := old
	s.DNS = []string{ip}
	s.Automatic = false
	if runtime.GOOS == "linux" {
		s.Values = []string{ip, "yes", "", "yes"}
	}
	return s
}

func Flush(ctx context.Context) error {
	var err error
	switch runtime.GOOS {
	case "darwin":
		_, err = diag.SystemCommand(ctx, "dscacheutil", "-flushcache")
		if err == nil {
			_, err = diag.SystemCommand(ctx, "killall", "-HUP", "mDNSResponder")
		}
	case "windows":
		_, err = diag.SystemCommand(ctx, "ipconfig.exe", "/flushdns")
	case "linux":
		_, err = diag.SystemCommand(ctx, "resolvectl", "flush-caches")
	default:
		err = errors.New("операция не поддерживается")
	}
	return err
}
