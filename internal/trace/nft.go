package trace

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type nftBackend struct{}

func (nftBackend) Name() BackendName {
	return BackendNFT
}

func (nftBackend) Run(ctx context.Context, exec Executor, cfg RunConfig, runID string) (result Result, err error) {
	result = baseResult(cfg, BackendNFT)
	result.RunID = runID
	table := "nftracepath_" + runID
	defer func() {
		if cleanupErr := cleanupShell(exec, privileged(nftCleanupScript(table), cfg.Target.Sudo)); cleanupErr != nil {
			result.CleanupError = cleanupErr.Error()
		}
	}()

	traceCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	monitorScript := privileged("nft monitor trace", cfg.Target.Sudo)
	lines, errs, err := exec.Stream(traceCtx, monitorScript)
	if err != nil {
		return result, fmt.Errorf("start nft monitor trace: %w", err)
	}

	setupScript := nftSetupScript(cfg, table, runID)
	if cfg.Debug {
		result.DebugRules = debugLines(setupScript)
	}
	if _, err := exec.Shell(ctx, privileged(setupScript, cfg.Target.Sudo)); err != nil {
		cancel()
		return result, fmt.Errorf("install nft trace rules: %w", err)
	}
	rulesOut, err := exec.Shell(ctx, privileged("nft --handle list ruleset", cfg.Target.Sudo))
	if err != nil {
		result.Warnings = append(result.Warnings, "could not snapshot nft ruleset after setup: "+err.Error())
	}
	rules := parseNFTRuleset(rulesOut)

	if cfg.Mode == ModeActive {
		if warning := maybeTriggerActive(traceCtx, exec, cfg); warning != "" {
			result.Warnings = append(result.Warnings, warning)
		}
	}

	tracked := map[string]bool{}
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
			ev, ok := parseNFTTraceLine(line, rules)
			if !ok {
				continue
			}
			if flowMatchesNFTLine(line, cfg.Flow) || strings.Contains(line, "nftracepath:"+runID) {
				tracked[ev.TraceID] = true
			}
			if !tracked[ev.TraceID] {
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

func nftSetupScript(cfg RunConfig, table, runID string) string {
	f := cfg.Flow
	preMatch := nftMatch(f, true)
	outMatch := nftMatch(f, false)
	limit := nftLimitExpr(cfg)
	cmds := []string{
		"add table inet " + table,
		"add chain inet " + table + " trace_prerouting { type filter hook prerouting priority -300; policy accept; }",
	}
	if shouldInstallOutputTrace(f) {
		cmds = append(cmds, "add chain inet "+table+" trace_output { type filter hook output priority -300; policy accept; }")
	}
	cmds = append(cmds,
		"add chain inet "+table+" final_input { type filter hook input priority 300; policy accept; }",
		"add chain inet "+table+" final_forward { type filter hook forward priority 300; policy accept; }",
		"add chain inet "+table+" final_postrouting { type filter hook postrouting priority 300; policy accept; }",
		"add rule inet "+table+" trace_prerouting "+preMatch+" "+limit+" meta nftrace set 1 counter comment "+strconvQuote(comment(runID, "trace-prerouting")),
	)
	if shouldInstallOutputTrace(f) {
		cmds = append(cmds, "add rule inet "+table+" trace_output "+outMatch+" "+limit+" meta nftrace set 1 counter comment "+strconvQuote(comment(runID, "trace-output")))
	}
	cmds = append(cmds,
		"add rule inet "+table+" final_input "+preMatch+" "+limit+" counter comment "+strconvQuote(comment(runID, "final-input")),
		"add rule inet "+table+" final_forward "+preMatch+" "+limit+" counter comment "+strconvQuote(comment(runID, "final-forward")),
		"add rule inet "+table+" final_postrouting "+outMatch+" "+limit+" counter comment "+strconvQuote(comment(runID, "final-postrouting")),
	)
	return nftBatchScript(cmds)
}

func nftLimitExpr(cfg RunConfig) string {
	return fmt.Sprintf("limit rate %s burst %d packets", cfg.TraceLimit, cfg.TraceLimitBurst)
}

func nftCleanupScript(table string) string {
	return "nft delete table inet " + shellQuote(table) + " >/dev/null 2>&1 || true"
}

func nftBatchScript(commands []string) string {
	return "nft -f - <<'NFTP_NFT_EOF'\n" + strings.Join(commands, "\n") + "\nNFTP_NFT_EOF"
}

func strconvQuote(s string) string {
	return fmt.Sprintf("%q", s)
}

func streamErr(errs <-chan error) error {
	select {
	case err, ok := <-errs:
		if ok && err != nil {
			return err
		}
	default:
	}
	return nil
}

func applyEventOutcome(result *Result, ev Event) {
	if ev.InIface != "" && result.InIface == "" {
		result.InIface = ev.InIface
	}
	if ev.OutIface != "" {
		result.OutIface = ev.OutIface
	}
	v := strings.ToLower(ev.Verdict)
	switch v {
	case "drop":
		result.Outcome = OutcomeDrop
		return
	case "reject":
		result.Outcome = OutcomeReject
		return
	}
	switch ev.FinalHint {
	case "input":
		result.Outcome = OutcomeLocal
	case "postrouting":
		result.Outcome = OutcomeEgress
	case "forward":
		if result.Outcome == OutcomeTimeout {
			result.Outcome = OutcomeUnknown
		}
	}
}

func isTerminal(outcome Outcome) bool {
	return outcome == OutcomeLocal || outcome == OutcomeEgress || outcome == OutcomeDrop || outcome == OutcomeReject
}

func shortSleep(ctx context.Context) {
	t := time.NewTimer(150 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func cleanupShell(exec Executor, script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := exec.Shell(ctx, script)
	return err
}
