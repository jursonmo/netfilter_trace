package trace

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func WriteJSON(w io.Writer, result Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func WriteHuman(w io.Writer, result Result) error {
	fmt.Fprintf(w, "Run ID:   %s\n", result.RunID)
	fmt.Fprintf(w, "Flow:     %s\n", result.Flow.String())
	fmt.Fprintf(w, "Backend:  %s\n", result.Backend)
	fmt.Fprintf(w, "Mode:     %s\n", result.Mode)
	fmt.Fprintf(w, "Outcome:  %s\n", result.Outcome)
	if result.InIface != "" {
		fmt.Fprintf(w, "Ingress:  %s\n", result.InIface)
	}
	if result.OutIface != "" {
		fmt.Fprintf(w, "Egress:   %s\n", result.OutIface)
	}
	fmt.Fprintf(w, "Duration: %s\n", result.Duration.Round(0))
	if len(result.Warnings) > 0 {
		fmt.Fprintln(w, "\nWarnings:")
		for _, warning := range result.Warnings {
			fmt.Fprintf(w, "  - %s\n", warning)
		}
	}
	if result.CleanupError != "" {
		fmt.Fprintf(w, "\nCleanup error: %s\n", result.CleanupError)
	}
	if len(result.DebugRules) > 0 {
		fmt.Fprintln(w, "\nDebug rules:")
		for _, line := range result.DebugRules {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	if len(result.Events) == 0 {
		fmt.Fprintln(w, "\nNo matching netfilter trace events were observed before timeout.")
		return nil
	}
	fmt.Fprintln(w, "\nEvents:")
	fmt.Fprintf(w, "%-4s %-9s %-12s %-18s %-9s %-10s %-10s %s\n", "#", "kind", "table", "chain", "verdict", "in", "out", "rule/raw")
	for i, ev := range result.Events {
		rule := ev.RuleRef.Rule
		if rule == "" {
			rule = ev.Raw
		}
		rule = compact(rule, 96)
		table := ev.RuleRef.Table
		if table == "" {
			table = ev.RuleRef.Family
		}
		chain := ev.RuleRef.Chain
		if ev.RuleRef.Number != 0 {
			chain = fmt.Sprintf("%s:%d", chain, ev.RuleRef.Number)
		} else if ev.RuleRef.Handle != "" {
			chain = fmt.Sprintf("%s#%s", chain, ev.RuleRef.Handle)
		}
		fmt.Fprintf(w, "%-4d %-9s %-12s %-18s %-9s %-10s %-10s %s\n",
			i+1, value(ev.Kind), value(table), value(chain), value(ev.Verdict), value(ev.InIface), value(ev.OutIface), rule)
	}
	return nil
}

func compact(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func value(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
