package diag

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

func Catalog(mode string) []Target {
	if mode == "vpn" {
		return []Target{{"YouTube", "https://www.youtube.com/"}, {"Telegram Web", "https://web.telegram.org/"}, {"Discord", "https://discord.com/"}, {"WhatsApp Web", "https://web.whatsapp.com/"}, {"GitHub", "https://github.com/"}, {"Wikipedia", "https://www.wikipedia.org/"}}
	}
	return []Target{{"Яндекс", "https://ya.ru/"}, {"Mail", "https://mail.ru/"}, {"VK", "https://vk.com/"}, {"Ozon", "https://www.ozon.ru/"}, {"Госуслуги", "https://www.gosuslugi.ru/"}, {"Rutube", "https://rutube.ru/"}}
}

func NormalizeTarget(raw string) (Target, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return Target{}, fmt.Errorf("нужен домен или HTTP(S)-адрес")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return Target{}, fmt.Errorf("поддерживаются только HTTP и HTTPS")
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		host, err = idna.Lookup.ToASCII(host)
	}
	if err != nil {
		return Target{}, fmt.Errorf("некорректный домен")
	}
	if strings.ContainsAny(host, "\r\n\t ") {
		return Target{}, fmt.Errorf("некорректный домен")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("порт должен быть от 1 до 65535")
		}
		host = net.JoinHostPort(host, u.Port())
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u = &url.URL{Scheme: u.Scheme, Host: host, Path: "/"}
	return Target{Name: u.Host, URL: u.String()}, nil
}
