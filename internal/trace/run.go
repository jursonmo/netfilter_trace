package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type backend interface {
	Name() BackendName
	Run(context.Context, Executor, RunConfig, string) (Result, error)
}

const terminalDrainDuration = 250 * time.Millisecond

type terminalDrain struct {
	timer *time.Timer
	C     <-chan time.Time
}

func (d *terminalDrain) Arm() {
	if d.timer != nil {
		return
	}
	d.timer = time.NewTimer(terminalDrainDuration)
	d.C = d.timer.C
}

func (d *terminalDrain) Stop() {
	if d.timer != nil {
		d.timer.Stop()
	}
}

func Run(ctx context.Context, exec Executor, cfg RunConfig) (Result, error) {
	cfg = normalizeConfig(cfg)
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	runID, err := newRunID()
	if err != nil {
		return Result{}, err
	}
	if err := checkPrivilege(ctx, exec, cfg.Target.Sudo); err != nil {
		return Result{}, err
	}
	selected, err := selectBackend(ctx, exec, cfg)
	if err != nil {
		return Result{}, err
	}
	result, err := selected.Run(ctx, exec, cfg, runID)
	result.RunID = runID
	result.Flow = cfg.Flow
	result.Mode = cfg.Mode
	result.Target = cfg.Target
	result.Backend = selected.Name()
	return result, err
}

func normalizeConfig(cfg RunConfig) RunConfig {
	if cfg.Target.Kind == "" {
		cfg.Target.Kind = TargetLocal
	}
	if cfg.Target.Kind == TargetSSH && cfg.Target.SSHPort == 0 {
		cfg.Target.SSHPort = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Backend == "" {
		cfg.Backend = BackendAuto
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeListen
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = DefaultMaxEvents
	}
	if cfg.TraceLimit == "" {
		cfg.TraceLimit = DefaultTraceLimit
	}
	if cfg.TraceLimitBurst == 0 {
		cfg.TraceLimitBurst = DefaultTraceLimitBurst
	}
	return cfg
}

func checkPrivilege(ctx context.Context, exec Executor, sudo bool) error {
	if sudo {
		if _, err := exec.Shell(ctx, "sudo -n true"); err != nil {
			return fmt.Errorf("sudo -n is not available on target: %w", err)
		}
		return nil
	}
	out, err := exec.Shell(ctx, "id -u")
	if err != nil {
		return fmt.Errorf("check target uid: %w", err)
	}
	if strings.TrimSpace(out) != "0" {
		return fmt.Errorf("target commands require root; rerun as root or pass --sudo")
	}
	return nil
}

func selectBackend(ctx context.Context, exec Executor, cfg RunConfig) (backend, error) {
	switch cfg.Backend {
	case BackendNFT:
		return nftBackend{}, nil
	case BackendIPTables:
		return iptablesBackend{}, nil
	case BackendAuto:
	default:
		return nil, fmt.Errorf("unsupported backend %q", cfg.Backend)
	}

	probe := probeBackends(ctx, exec, cfg.Target.Sudo)
	if probe.iptablesAvailable && probe.iptablesRules > 0 {
		return iptablesBackend{}, nil
	}
	if probe.nftAvailable && probe.nftRules > 0 {
		return nftBackend{}, nil
	}
	if probe.nftAvailable {
		return nftBackend{}, nil
	}
	if probe.iptablesAvailable {
		return iptablesBackend{}, nil
	}
	return nil, fmt.Errorf("no supported netfilter backend found: need nft or iptables/iptables-save")
}

type backendProbe struct {
	nftAvailable      bool
	nftRules          int
	iptablesAvailable bool
	iptablesRules     int
}

func probeBackends(ctx context.Context, exec Executor, sudo bool) backendProbe {
	var probe backendProbe
	if out, err := exec.Shell(ctx, privileged("command -v nft >/dev/null 2>&1 && nft --handle list ruleset", sudo)); err == nil {
		probe.nftAvailable = true
		probe.nftRules = len(parseNFTRuleset(out))
	}
	if tools, err := detectIPTablesLegacyTools(ctx, exec, sudo); err == nil {
		probe.iptablesAvailable = true
		probe.iptablesRules = tools.Rules
	}
	return probe
}

func newRunID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func baseResult(cfg RunConfig, backend BackendName) Result {
	started := time.Now()
	return Result{
		Flow:      cfg.Flow,
		Backend:   backend,
		Mode:      cfg.Mode,
		Target:    cfg.Target,
		StartedAt: started,
		Outcome:   OutcomeTimeout,
	}
}

func finishResult(result *Result) {
	result.FinishedAt = time.Now()
	result.Duration = result.FinishedAt.Sub(result.StartedAt)
	if result.InIface == "" {
		for _, ev := range result.Events {
			if ev.InIface != "" {
				result.InIface = ev.InIface
				break
			}
		}
	}
	if result.OutIface == "" {
		for _, ev := range result.Events {
			if ev.OutIface != "" {
				result.OutIface = ev.OutIface
			}
		}
	}
}

func reachedMaxEvents(result *Result, cfg RunConfig) bool {
	if len(result.Events) < cfg.MaxEvents {
		return false
	}
	if result.Outcome == OutcomeTimeout {
		result.Outcome = OutcomeUnknown
	}
	result.Warnings = append(result.Warnings, fmt.Sprintf("stopped after max-events=%d to limit kernel TRACE/LOG output", cfg.MaxEvents))
	return true
}

func debugLines(script string) []string {
	lines := []string{}
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
