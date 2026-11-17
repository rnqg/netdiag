package diag

import (
	"encoding/json"
	"fmt"
	"time"
)

const Version = "0.1.3"
const Schema = 1

type Target struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Sample struct {
	Sequence  int       `json:"sequence"`
	At        time.Time `json:"at"`
	RTT       float64   `json:"rtt_ms"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	Size      int       `json:"size,omitempty"`
	SendError bool      `json:"send_error,omitempty"`
	Late      bool      `json:"late,omitempty"`
	LateRTT   *float64  `json:"late_reply_rtt_ms,omitempty"`
}

type Statistics struct {
	Attempts    int      `json:"attempts"`
	LocalErrors int      `json:"local_send_errors"`
	LateReplies int      `json:"late_replies"`
	Sent        int      `json:"sent"`
	Received    int      `json:"received"`
	Lost        int      `json:"lost"`
	LossPercent float64  `json:"loss_percent"`
	LongestLoss int      `json:"longest_loss_burst"`
	Min         float64  `json:"min_ms"`
	Median      float64  `json:"median_ms"`
	P95         float64  `json:"p95_ms"`
	P99         *float64 `json:"p99_ms,omitempty"`
	Max         float64  `json:"max_ms"`
	Jitter      float64  `json:"adjacent_rtt_jitter_ms"`
	JitterPairs int      `json:"jitter_pairs"`
	Duplicates  int      `json:"duplicates"`
	Reordered   int      `json:"reordered"`
}

func (s Statistics) MarshalJSON() ([]byte, error) {
	type alias Statistics
	w := struct {
		alias
		Min    *float64 `json:"min_ms"`
		Median *float64 `json:"median_ms"`
		P95    *float64 `json:"p95_ms"`
		Max    *float64 `json:"max_ms"`
		Jitter *float64 `json:"adjacent_rtt_jitter_ms"`
	}{alias: alias(s)}
	if s.Received > 0 {
		w.Min = &s.Min
		w.Median = &s.Median
		w.P95 = &s.P95
		w.Max = &s.Max
	}
	if s.JitterPairs > 0 {
		w.Jitter = &s.Jitter
	}
	return json.Marshal(w)
}

func (s Sample) MarshalJSON() ([]byte, error) {
	type alias Sample
	w := struct {
		alias
		RTT *float64 `json:"rtt_ms"`
	}{alias: alias(s)}
	if s.OK {
		w.RTT = &s.RTT
	}
	return json.Marshal(w)
}

type Measurement struct {
	ID         string         `json:"id"`
	Target     string         `json:"target"`
	Kind       string         `json:"kind"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason,omitempty"`
	Started    time.Time      `json:"started"`
	DurationMS float64        `json:"duration_ms"`
	Data       map[string]any `json:"data,omitempty"`
	Samples    []Sample       `json:"samples,omitempty"`
	Stats      *Statistics    `json:"statistics,omitempty"`
}

type Finding struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence"`
	Next       string   `json:"next"`
	FixID      string   `json:"fix_id,omitempty"`
}

type Interface struct {
	Name     string `json:"-"`
	Index    int    `json:"-"`
	MTU      int    `json:"mtu"`
	Up       bool   `json:"up"`
	Loopback bool   `json:"loopback"`
	IPv4     bool   `json:"ipv4"`
	IPv6     bool   `json:"ipv6"`
	VPNHint  bool   `json:"vpn_hint"`
}

type Environment struct {
	OS                string            `json:"os"`
	Arch              string            `json:"arch"`
	Interfaces        []Interface       `json:"interfaces"`
	VPNHint           bool              `json:"vpn_hint"`
	ProxyHint         bool              `json:"proxy_hint"`
	RouteAvailable    bool              `json:"route_available"`
	RouteReason       string            `json:"route_reason,omitempty"`
	ActiveInterface   string            `json:"-"`
	Gateway           string            `json:"-"`
	PhysicalInterface string            `json:"-"`
	PhysicalGateway   string            `json:"-"`
	DNSFingerprint    string            `json:"-"`
	ProxyStateKnown   bool              `json:"-"`
	Fingerprint       string            `json:"-"`
	LinkFingerprint   string            `json:"-"`
	Capabilities      map[string]string `json:"capabilities"`
}

type Report struct {
	Schema         int               `json:"schema_version"`
	Version        string            `json:"version"`
	Catalog        string            `json:"catalog_version"`
	Rules          string            `json:"rules_version"`
	Started        time.Time         `json:"started"`
	Finished       time.Time         `json:"finished"`
	Command        string            `json:"command"`
	Mode           string            `json:"mode"`
	Profile        string            `json:"profile"`
	Environment    Environment       `json:"environment"`
	Targets        []Target          `json:"targets,omitempty"`
	Measurements   []Measurement     `json:"measurements"`
	Findings       []Finding         `json:"findings"`
	Partial        bool              `json:"partial"`
	NetworkChanged bool              `json:"network_changed"`
	Full           bool              `json:"full,omitempty"`
	Methods        map[string]string `json:"methods"`
}

type Options struct {
	Mode       string
	Profile    string
	Targets    []Target
	Duration   time.Duration
	Node       string
	NodeToken  string
	AcceptMLab bool
	MaxBytes   int64
	Traceroute bool
	Progress   func(string)
}

func NewReport(command string, opts Options) Report {
	return Report{Schema: Schema, Version: Version, Catalog: "2026-11-17.1", Rules: "2", Started: time.Now().UTC(), Command: command, Mode: opts.Mode, Profile: opts.Profile, Environment: Inspect(), Targets: opts.Targets, Measurements: []Measurement{}, Findings: []Finding{}, Methods: map[string]string{
		"rtt":         "ICMP или аутентифицированный UDP echo; время соединения и HTTP учитывается отдельно",
		"jitter":      "mean(abs(RTT[i]-RTT[i-1])) только для последовательных успешных проб",
		"percentile":  "nearest-rank; p99 при числе успешных проб >= 100",
		"loss":        "ответ не получен до срока ожидания; это потеря ответа пробы, а не оценка всех пакетов сети",
		"bufferbloat": "p95 RTT под нагрузкой минус p95 исходного RTT; сравниваются один узел и один метод",
		"scope":       "Прямые запросы утилиты по маршрутам ОС; браузерные прокси, PAC и правила для других процессов могут отличаться",
	}}
}

func (r *Report) Finish(ctxErr error) {
	r.Finished = time.Now().UTC()
	r.Partial = r.Partial || ctxErr != nil
	for i := range r.Measurements {
		if r.Measurements[i].ID == "" {
			r.Measurements[i].ID = fmt.Sprintf("%s-%03d", r.Measurements[i].Kind, i)
		}
		if r.Measurements[i].Status == "partial" || r.Measurements[i].Status == "limited" {
			r.Partial = true
		}
	}
	r.NetworkChanged = r.NetworkChanged || !SameNetwork(r.Environment, Inspect())
	if r.NetworkChanged {
		r.Partial = true
	}
	r.Findings = Analyze(*r)
}
