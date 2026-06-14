package trace

import (
	"context"
	"fmt"
	"strings"
)

type iptablesBackend struct{}

func (iptablesBackend) Name() BackendName {
	return BackendIPTables
}

func (iptablesBackend) Run(ctx context.Context, exec Executor, cfg RunConfig, runID string) (result Result, err error) {
	result = baseResult(cfg, BackendIPTables)
	result.RunID = runID
	defer func() {
		if cleanupErr := cleanupShell(exec, privileged(iptablesCleanupScript(cfg, runID), cfg.Target.Sudo)); cleanupErr != nil {
			result.CleanupError = cleanupErr.Error()
		}
	}()

	traceCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	monitorScript := privileged(iptablesMonitorScript(), cfg.Target.Sudo)
	lines, errs, err := exec.Stream(traceCtx, monitorScript)
	if err != nil {
		return result, fmt.Errorf("start kernel log monitor: %w", err)
	}

	setupScript := iptablesSetupScript(cfg, runID)
	if cfg.Debug {
		result.DebugRules = debugLines(setupScript)
	}
	if _, err := exec.Shell(ctx, privileged(setupScript, cfg.Target.Sudo)); err != nil {
		cancel()
		return result, fmt.Errorf("install iptables trace rules: %w", err)
	}
	snapshot, err := exec.Shell(ctx, privileged("iptables-save", cfg.Target.Sudo))
	if err != nil {
		result.Warnings = append(result.Warnings, "could not snapshot iptables-save after setup: "+err.Error())
	}
	rules := parseIPTablesSave(snapshot)

	if cfg.Mode == ModeActive {
		if warning := maybeTriggerActive(traceCtx, exec, cfg); warning != "" {
			result.Warnings = append(result.Warnings, warning)
		}
	}

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				finishResult(&result)
				if result.Outcome == OutcomeTimeout && len(result.Events) > 0 {
					result.Outcome = OutcomeUnknown
				}
				return result, streamErr(errs)
			}
			if !(strings.Contains(line, "NFTP:"+runID) || flowMatchesLog(line, cfg.Flow)) {
				continue
			}
			ev, ok := parseIPTablesLogLine(line, rules)
			if !ok {
				continue
			}
			result.Events = append(result.Events, ev)
			applyEventOutcome(&result, ev)
			if isTerminal(result.Outcome) {
				finishResult(&result)
				return result, nil
			}
			if reachedMaxEvents(&result, cfg) {
				finishResult(&result)
				return result, nil
			}
		case <-traceCtx.Done():
			finishResult(&result)
			if len(result.Events) > 0 && result.Outcome == OutcomeTimeout {
				result.Outcome = OutcomeUnknown
			}
			return result, nil
		}
	}
}

func iptablesMonitorScript() string {
	return "if command -v journalctl >/dev/null 2>&1; then journalctl -k -f -n 0 -o cat; elif dmesg --help 2>&1 | grep -q -- ' -W'; then dmesg -W; else dmesg -w; fi"
}

func iptablesSetupScript(cfg RunConfig, runID string) string {
	f := cfg.Flow
	preArgs := iptablesMatchArgs(f, true)
	outArgs := iptablesMatchArgs(f, false)
	limitArgs := iptablesLimitArgs(cfg)
	cmds := []string{
		iptablesInsert("raw", "PREROUTING", preArgs, iptablesTail(limitArgs, comment(runID, "trace-prerouting"), "TRACE", "")),
	}
	if shouldInstallOutputTrace(f) {
		cmds = append(cmds, iptablesInsert("raw", "OUTPUT", outArgs, iptablesTail(limitArgs, comment(runID, "trace-output"), "TRACE", "")))
	}
	cmds = append(cmds,
		iptablesAppend("", "INPUT", preArgs, iptablesTail(limitArgs, comment(runID, "final-input"), "LOG", logPrefix(runID, "IN"))),
		iptablesAppend("", "FORWARD", preArgs, iptablesTail(limitArgs, comment(runID, "final-forward"), "LOG", logPrefix(runID, "FWD"))),
		iptablesAppend("mangle", "POSTROUTING", outArgs, iptablesTail(limitArgs, comment(runID, "final-postrouting"), "LOG", logPrefix(runID, "POST"))),
	)
	return strings.Join(cmds, "\n")
}

func iptablesCleanupScript(cfg RunConfig, runID string) string {
	f := cfg.Flow
	preArgs := iptablesMatchArgs(f, true)
	outArgs := iptablesMatchArgs(f, false)
	limitArgs := iptablesLimitArgs(cfg)
	cmds := []string{
		iptablesDelete("mangle", "POSTROUTING", outArgs, iptablesTail(limitArgs, comment(runID, "final-postrouting"), "LOG", logPrefix(runID, "POST"))),
		iptablesDelete("", "FORWARD", preArgs, iptablesTail(limitArgs, comment(runID, "final-forward"), "LOG", logPrefix(runID, "FWD"))),
		iptablesDelete("", "INPUT", preArgs, iptablesTail(limitArgs, comment(runID, "final-input"), "LOG", logPrefix(runID, "IN"))),
	}
	if shouldInstallOutputTrace(f) {
		cmds = append(cmds, iptablesDelete("raw", "OUTPUT", outArgs, iptablesTail(limitArgs, comment(runID, "trace-output"), "TRACE", "")))
	}
	cmds = append(cmds, iptablesDelete("raw", "PREROUTING", preArgs, iptablesTail(limitArgs, comment(runID, "trace-prerouting"), "TRACE", "")))
	return strings.Join(cmds, "\n")
}

func shouldInstallOutputTrace(f Flow) bool {
	return f.InIface == ""
}

func iptablesLimitArgs(cfg RunConfig) []string {
	return []string{"-m", "limit", "--limit", cfg.TraceLimit, "--limit-burst", fmt.Sprintf("%d", cfg.TraceLimitBurst)}
}

func iptablesTail(limitArgs []string, commentText, target, logPrefixText string) []string {
	args := append([]string{}, limitArgs...)
	args = append(args, "-m", "comment", "--comment", commentText, "-j", target)
	if logPrefixText != "" {
		args = append(args, "--log-prefix", logPrefixText)
	}
	return args
}

func iptablesInsert(table, chain string, match, tail []string) string {
	args := []string{"iptables"}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-I", chain, "1")
	args = append(args, match...)
	args = append(args, tail...)
	return shellJoin(args)
}

func iptablesAppend(table, chain string, match, tail []string) string {
	args := []string{"iptables"}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-A", chain)
	args = append(args, match...)
	args = append(args, tail...)
	return shellJoin(args)
}

func iptablesDelete(table, chain string, match, tail []string) string {
	args := []string{"iptables"}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-D", chain)
	args = append(args, match...)
	args = append(args, tail...)
	return shellJoin(args) + " >/dev/null 2>&1 || true"
}
