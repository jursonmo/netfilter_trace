package trace

import (
	"context"
	"fmt"
	"strings"
)

type iptablesBackend struct{}

type iptablesLegacyTools struct {
	Command     string
	SaveCommand string
	Rules       int
}

func (iptablesBackend) Name() BackendName {
	return BackendIPTables
}

func (iptablesBackend) Run(ctx context.Context, exec Executor, cfg RunConfig, runID string) (result Result, err error) {
	result = baseResult(cfg, BackendIPTables)
	result.RunID = runID
	tools, err := detectIPTablesLegacyTools(ctx, exec, cfg.Target.Sudo)
	if err != nil {
		return result, err
	}
	if tools.Rules == 0 {
		result.Warnings = append(result.Warnings, "iptables-legacy ruleset is empty; if target rules were added by iptables-nft/default iptables, use --backend nft")
	}
	defer func() {
		if cleanupErr := cleanupShell(exec, privileged(iptablesCleanupScriptWithCommand(cfg, runID, tools.Command), cfg.Target.Sudo)); cleanupErr != nil {
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

	setupScript := iptablesSetupScriptWithCommand(cfg, runID, tools.Command)
	if cfg.Debug {
		result.DebugRules = debugLines(setupScript)
	}
	if _, err := exec.Shell(ctx, privileged(setupScript, cfg.Target.Sudo)); err != nil {
		cancel()
		return result, fmt.Errorf("install iptables trace rules: %w", err)
	}
	snapshot, err := exec.Shell(ctx, privileged(tools.SaveCommand, cfg.Target.Sudo))
	if err != nil {
		result.Warnings = append(result.Warnings, "could not snapshot "+tools.SaveCommand+" after setup: "+err.Error())
	}
	rules := parseIPTablesSave(snapshot)

	if cfg.Mode == ModeActive {
		if warning := maybeTriggerActive(traceCtx, exec, cfg); warning != "" {
			result.Warnings = append(result.Warnings, warning)
		}
	}

	var drain terminalDrain
	defer drain.Stop()
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
			annotateRuleOrigin(&ev, runID)
			result.Events = append(result.Events, ev)
			applyEventOutcome(&result, ev)
			if isTerminal(result.Outcome) {
				drain.Arm()
			}
			if reachedMaxEvents(&result, cfg) {
				finishResult(&result)
				return result, nil
			}
		case <-drain.C:
			finishResult(&result)
			return result, nil
		case <-traceCtx.Done():
			finishResult(&result)
			if len(result.Events) > 0 && result.Outcome == OutcomeTimeout {
				result.Outcome = OutcomeUnknown
			}
			return result, nil
		}
	}
}

func detectIPTablesLegacyTools(ctx context.Context, exec Executor, sudo bool) (iptablesLegacyTools, error) {
	if out, err := exec.Shell(ctx, privileged("command -v iptables-legacy >/dev/null 2>&1 && command -v iptables-legacy-save >/dev/null 2>&1 && iptables-legacy --version", sudo)); err == nil && strings.Contains(strings.ToLower(out), "legacy") {
		saveOut, saveErr := exec.Shell(ctx, privileged("iptables-legacy-save", sudo))
		if saveErr != nil {
			return iptablesLegacyTools{}, fmt.Errorf("snapshot iptables-legacy-save: %w", saveErr)
		}
		return iptablesLegacyTools{Command: "iptables-legacy", SaveCommand: "iptables-legacy-save", Rules: len(parseIPTablesSave(saveOut))}, nil
	}

	out, err := exec.Shell(ctx, privileged("command -v iptables >/dev/null 2>&1 && command -v iptables-save >/dev/null 2>&1 && iptables --version", sudo))
	if err != nil {
		return iptablesLegacyTools{}, fmt.Errorf("iptables backend requires iptables-legacy or legacy iptables: %w", err)
	}
	if !strings.Contains(strings.ToLower(out), "legacy") {
		return iptablesLegacyTools{}, fmt.Errorf("iptables backend requires iptables-legacy; default iptables is %q, use --backend nft for iptables-nft/nf_tables rules", strings.TrimSpace(out))
	}
	saveOut, saveErr := exec.Shell(ctx, privileged("iptables-save", sudo))
	if saveErr != nil {
		return iptablesLegacyTools{}, fmt.Errorf("snapshot iptables-save: %w", saveErr)
	}
	return iptablesLegacyTools{Command: "iptables", SaveCommand: "iptables-save", Rules: len(parseIPTablesSave(saveOut))}, nil
}

func iptablesMonitorScript() string {
	return "if command -v journalctl >/dev/null 2>&1; then journalctl -k -f -n 0 -o cat; elif dmesg --help 2>&1 | grep -q -- ' -W'; then dmesg -W; else dmesg -w; fi"
}

func iptablesSetupScript(cfg RunConfig, runID string) string {
	return iptablesSetupScriptWithCommand(cfg, runID, "iptables")
}

func iptablesSetupScriptWithCommand(cfg RunConfig, runID, command string) string {
	f := cfg.Flow
	preArgs := iptablesMatchArgs(f, true)
	outArgs := iptablesMatchArgs(f, false)
	limitArgs := iptablesLimitArgs(cfg)
	cmds := []string{
		iptablesInsert(command, "raw", "PREROUTING", preArgs, iptablesTail(limitArgs, comment(runID, "trace-prerouting"), "TRACE", "")),
	}
	if shouldInstallOutputTrace(f) {
		cmds = append(cmds, iptablesInsert(command, "raw", "OUTPUT", outArgs, iptablesTail(limitArgs, comment(runID, "trace-output"), "TRACE", "")))
	}
	cmds = append(cmds,
		iptablesAppend(command, "", "INPUT", preArgs, iptablesTail(limitArgs, comment(runID, "final-input"), "LOG", logPrefix(runID, "IN"))),
		iptablesAppend(command, "", "FORWARD", preArgs, iptablesTail(limitArgs, comment(runID, "final-forward"), "LOG", logPrefix(runID, "FWD"))),
		iptablesAppend(command, "mangle", "POSTROUTING", outArgs, iptablesTail(limitArgs, comment(runID, "final-postrouting"), "LOG", logPrefix(runID, "POST"))),
	)
	return strings.Join(cmds, "\n")
}

func iptablesCleanupScript(cfg RunConfig, runID string) string {
	return iptablesCleanupScriptWithCommand(cfg, runID, "iptables")
}

func iptablesCleanupScriptWithCommand(cfg RunConfig, runID, command string) string {
	f := cfg.Flow
	preArgs := iptablesMatchArgs(f, true)
	outArgs := iptablesMatchArgs(f, false)
	limitArgs := iptablesLimitArgs(cfg)
	cmds := []string{
		iptablesDelete(command, "mangle", "POSTROUTING", outArgs, iptablesTail(limitArgs, comment(runID, "final-postrouting"), "LOG", logPrefix(runID, "POST"))),
		iptablesDelete(command, "", "FORWARD", preArgs, iptablesTail(limitArgs, comment(runID, "final-forward"), "LOG", logPrefix(runID, "FWD"))),
		iptablesDelete(command, "", "INPUT", preArgs, iptablesTail(limitArgs, comment(runID, "final-input"), "LOG", logPrefix(runID, "IN"))),
	}
	if shouldInstallOutputTrace(f) {
		cmds = append(cmds, iptablesDelete(command, "raw", "OUTPUT", outArgs, iptablesTail(limitArgs, comment(runID, "trace-output"), "TRACE", "")))
	}
	cmds = append(cmds, iptablesDelete(command, "raw", "PREROUTING", preArgs, iptablesTail(limitArgs, comment(runID, "trace-prerouting"), "TRACE", "")))
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

func iptablesInsert(command, table, chain string, match, tail []string) string {
	args := []string{command}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-I", chain, "1")
	args = append(args, match...)
	args = append(args, tail...)
	return shellJoin(args)
}

func iptablesAppend(command, table, chain string, match, tail []string) string {
	args := []string{command}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-A", chain)
	args = append(args, match...)
	args = append(args, tail...)
	return shellJoin(args)
}

func iptablesDelete(command, table, chain string, match, tail []string) string {
	args := []string{command}
	if table != "" {
		args = append(args, "-t", table)
	}
	args = append(args, "-D", chain)
	args = append(args, match...)
	args = append(args, tail...)
	return shellJoin(args) + " >/dev/null 2>&1 || true"
}
