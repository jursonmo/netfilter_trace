package trace

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultMaxEvents       = 200
	DefaultTraceLimit      = "10/second"
	DefaultTraceLimitBurst = 20
)

type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

type Mode string

const (
	ModeListen Mode = "listen"
	ModeActive Mode = "active"
)

type BackendName string

const (
	BackendAuto     BackendName = "auto"
	BackendNFT      BackendName = "nft"
	BackendIPTables BackendName = "iptables"
)

type TargetKind string

const (
	TargetLocal TargetKind = "local"
	TargetSSH   TargetKind = "ssh"
)

type Flow struct {
	Proto   Proto  `json:"proto"`
	SrcIP   net.IP `json:"src_ip"`
	SrcPort int    `json:"src_port,omitempty"`
	DstIP   net.IP `json:"dst_ip"`
	DstPort int    `json:"dst_port,omitempty"`
	InIface string `json:"in_iface,omitempty"`
}

type TargetConfig struct {
	Kind    TargetKind `json:"kind"`
	SSHHost string     `json:"ssh_host,omitempty"`
	SSHUser string     `json:"ssh_user,omitempty"`
	SSHPort int        `json:"ssh_port,omitempty"`
	SSHKey  string     `json:"ssh_key,omitempty"`
	Sudo    bool       `json:"sudo"`
}

type RunConfig struct {
	Flow            Flow          `json:"flow"`
	Mode            Mode          `json:"mode"`
	Backend         BackendName   `json:"backend"`
	Target          TargetConfig  `json:"target"`
	Timeout         time.Duration `json:"timeout"`
	MaxEvents       int           `json:"max_events"`
	TraceLimit      string        `json:"trace_limit"`
	TraceLimitBurst int           `json:"trace_limit_burst"`
	AllowBroadMatch bool          `json:"allow_broad_match"`
	Debug           bool          `json:"debug,omitempty"`
	JSON            bool          `json:"-"`
}

type RuleRef struct {
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Chain  string `json:"chain,omitempty"`
	Handle string `json:"handle,omitempty"`
	Number int    `json:"number,omitempty"`
	Origin string `json:"origin,omitempty"`
	Rule   string `json:"rule,omitempty"`
}

type Event struct {
	Time      time.Time `json:"time"`
	Backend   string    `json:"backend"`
	TraceID   string    `json:"trace_id,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	RuleRef   RuleRef   `json:"rule_ref,omitempty"`
	Verdict   string    `json:"verdict,omitempty"`
	InIface   string    `json:"in_iface,omitempty"`
	OutIface  string    `json:"out_iface,omitempty"`
	FinalHint string    `json:"final_hint,omitempty"`
	Raw       string    `json:"raw"`
}

type Outcome string

const (
	OutcomeTimeout Outcome = "timeout"
	OutcomeLocal   Outcome = "local"
	OutcomeEgress  Outcome = "egress"
	OutcomeDrop    Outcome = "drop"
	OutcomeReject  Outcome = "reject"
	OutcomeUnknown Outcome = "unknown"
)

type Result struct {
	RunID        string        `json:"run_id"`
	Flow         Flow          `json:"flow"`
	Backend      BackendName   `json:"backend"`
	Mode         Mode          `json:"mode"`
	Target       TargetConfig  `json:"target"`
	StartedAt    time.Time     `json:"started_at"`
	FinishedAt   time.Time     `json:"finished_at"`
	Duration     time.Duration `json:"duration"`
	Outcome      Outcome       `json:"outcome"`
	InIface      string        `json:"in_iface,omitempty"`
	OutIface     string        `json:"out_iface,omitempty"`
	Events       []Event       `json:"events"`
	Warnings     []string      `json:"warnings,omitempty"`
	DebugRules   []string      `json:"debug_rules,omitempty"`
	CleanupError string        `json:"cleanup_error,omitempty"`
}

func NewFlow(proto, src string, sport int, dst string, dport int, inIface string) (Flow, error) {
	f := Flow{
		Proto:   Proto(strings.ToLower(strings.TrimSpace(proto))),
		SrcIP:   net.ParseIP(strings.TrimSpace(src)),
		SrcPort: sport,
		DstIP:   net.ParseIP(strings.TrimSpace(dst)),
		DstPort: dport,
		InIface: strings.TrimSpace(inIface),
	}
	return f, f.Validate()
}

func (f Flow) Validate() error {
	if f.Proto != ProtoTCP && f.Proto != ProtoUDP {
		return fmt.Errorf("proto must be tcp or udp")
	}
	if f.SrcIP == nil || f.SrcIP.To4() == nil {
		return fmt.Errorf("src must be an IPv4 address")
	}
	if f.DstIP == nil || f.DstIP.To4() == nil {
		return fmt.Errorf("dst must be an IPv4 address")
	}
	if f.SrcPort < 0 || f.SrcPort > 65535 {
		return fmt.Errorf("source port must be in 0..65535")
	}
	if f.DstPort < 0 || f.DstPort > 65535 {
		return fmt.Errorf("destination port must be in 0..65535")
	}
	for _, r := range f.InIface {
		if !(r == '.' || r == '_' || r == '-' || r == ':' || r == '@' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return fmt.Errorf("in-iface contains unsupported characters")
		}
	}
	return nil
}

func (f Flow) Src4() string {
	return f.SrcIP.To4().String()
}

func (f Flow) Dst4() string {
	return f.DstIP.To4().String()
}

func (f Flow) String() string {
	return fmt.Sprintf("%s %s:%s -> %s:%s", f.Proto, f.Src4(), portString(f.SrcPort), f.Dst4(), portString(f.DstPort))
}

func portString(port int) string {
	if port == 0 {
		return "*"
	}
	return fmt.Sprintf("%d", port)
}

func (c RunConfig) Validate() error {
	if err := c.Flow.Validate(); err != nil {
		return err
	}
	if c.Flow.IsBroadPortMatch() && !c.AllowBroadMatch {
		return fmt.Errorf("source and destination ports are both omitted; pass --allow-broad-match to install broad TRACE/LOG rules")
	}
	if c.Mode != ModeListen && c.Mode != ModeActive {
		return fmt.Errorf("mode must be listen or active")
	}
	if c.Backend != BackendAuto && c.Backend != BackendNFT && c.Backend != BackendIPTables {
		return fmt.Errorf("backend must be auto, nft, or iptables")
	}
	if c.Target.Kind == "" {
		return fmt.Errorf("target must be local or ssh")
	}
	if c.Target.Kind != TargetLocal && c.Target.Kind != TargetSSH {
		return fmt.Errorf("target must be local or ssh")
	}
	if c.Target.Kind == TargetSSH && c.Target.SSHHost == "" {
		return fmt.Errorf("ssh target requires --ssh-host")
	}
	if c.Target.SSHPort == 0 {
		c.Target.SSHPort = 22
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	if c.MaxEvents < 1 {
		return fmt.Errorf("max-events must be greater than zero")
	}
	if !validTraceLimit(c.TraceLimit) {
		return fmt.Errorf("trace-limit must look like 10/second, 60/minute, or 100/hour")
	}
	if c.TraceLimitBurst < 1 {
		return fmt.Errorf("trace-limit-burst must be greater than zero")
	}
	return nil
}

func (f Flow) IsBroadPortMatch() bool {
	return f.SrcPort == 0 && f.DstPort == 0
}

var traceLimitRE = regexp.MustCompile(`^[1-9][0-9]*/(second|minute|hour|day)$`)

func validTraceLimit(limit string) bool {
	return traceLimitRE.MatchString(limit)
}
