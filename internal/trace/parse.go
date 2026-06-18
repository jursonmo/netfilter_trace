package trace

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ruleMap map[string]string

var (
	nftTraceRE       = regexp.MustCompile(`^trace id (\S+) (\S+) (\S+) (\S+) (packet|rule|verdict|policy):?\s*(.*)$`)
	nftHandleRE      = regexp.MustCompile(`(?:#\s*)?handle\s+(\d+)`)
	nftVerdictRE     = regexp.MustCompile(`(?i)\bverdict\s+([a-z]+)|\((?:verdict\s+)?([a-z]+)\)$`)
	iptablesTraceRE  = regexp.MustCompile(`TRACE:\s+([^:]+):([^:]+):([^:]+):([^ ]+)`)
	iptablesKVPairRE = regexp.MustCompile(`\b([A-Z]+)=([^ ]*)`)
)

func parseNFTRuleset(ruleset string) ruleMap {
	out := ruleMap{}
	var family, table, chain string
	for _, raw := range strings.Split(ruleset, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "table" {
			family, table = fields[1], fields[2]
			continue
		}
		if len(fields) >= 2 && fields[0] == "chain" {
			chain = fields[1]
			continue
		}
		if family == "" || table == "" || chain == "" {
			continue
		}
		handle := firstSubmatch(nftHandleRE, line)
		if handle == "" {
			continue
		}
		out[nftRuleKey(family, table, chain, handle)] = line
	}
	return out
}

func parseNFTTraceLine(line string, rules ruleMap) (Event, bool) {
	m := nftTraceRE.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Event{}, false
	}
	ev := Event{
		Time:    time.Now(),
		Backend: string(BackendNFT),
		TraceID: m[1],
		Kind:    m[5],
		RuleRef: RuleRef{
			Family: m[2],
			Table:  m[3],
			Chain:  m[4],
		},
		Raw: line,
	}
	rest := m[6]
	if handle := firstSubmatch(nftHandleRE, rest); handle != "" {
		ev.RuleRef.Handle = handle
		if rule := rules[nftRuleKey(ev.RuleRef.Family, ev.RuleRef.Table, ev.RuleRef.Chain, handle)]; rule != "" {
			ev.RuleRef.Rule = rule
		}
	}
	if ev.RuleRef.Rule == "" && ev.Kind == "rule" {
		ev.RuleRef.Rule = rest
	}
	ev.Verdict = parseVerdict(rest)
	ev.InIface = parseQuotedIface(rest, "iif")
	if ev.InIface == "" {
		ev.InIface = parseQuotedIface(rest, "iifname")
	}
	ev.OutIface = parseQuotedIface(rest, "oif")
	if ev.OutIface == "" {
		ev.OutIface = parseQuotedIface(rest, "oifname")
	}
	ev.FinalHint = parseFinalHint(ev.RuleRef.Chain + " " + ev.RuleRef.Rule + " " + rest)
	return ev, true
}

func parseIPTablesSave(snapshot string) ruleMap {
	out := ruleMap{}
	table := ""
	counts := map[string]int{}
	for _, raw := range strings.Split(snapshot, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if line == "COMMIT" {
			table = ""
			counts = map[string]int{}
			continue
		}
		if table == "" || !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chain := fields[1]
		key := table + "/" + chain
		counts[key]++
		out[iptablesRuleKey(table, chain, counts[key])] = line
	}
	return out
}

func parseIPTablesLogLine(line string, rules ruleMap) (Event, bool) {
	now := time.Now()
	if strings.Contains(line, "TRACE:") {
		m := iptablesTraceRE.FindStringSubmatch(line)
		if m == nil {
			return Event{}, false
		}
		ev := Event{
			Time:    now,
			Backend: string(BackendIPTables),
			Kind:    m[3],
			RuleRef: RuleRef{
				Table: m[1],
				Chain: m[2],
			},
			Raw: line,
		}
		if ev.Kind == "rule" {
			n, err := strconv.Atoi(m[4])
			if err != nil {
				return Event{}, false
			}
			ev.RuleRef.Number = n
			ev.RuleRef.Rule = rules[iptablesRuleKey(ev.RuleRef.Table, ev.RuleRef.Chain, n)]
		}
		ev.InIface, ev.OutIface = parseINOUT(line)
		ev.Verdict = parseIPTablesVerdict(ev)
		return ev, true
	}
	if strings.Contains(line, "NFTP:") {
		ev := Event{
			Time:      now,
			Backend:   string(BackendIPTables),
			Kind:      "log",
			Raw:       line,
			FinalHint: parseIPTablesFinalHint(line),
		}
		ev.InIface, ev.OutIface = parseINOUT(line)
		return ev, true
	}
	return Event{}, false
}

func annotateRuleOrigin(ev *Event, runID string) {
	if isTemporaryEvent(*ev, runID) {
		ev.RuleRef.Origin = "temporary"
		return
	}
	if ev.Kind == "policy" {
		ev.RuleRef.Origin = "policy"
		return
	}
	if isSystemEvent(*ev) {
		ev.RuleRef.Origin = "system"
	}
}

func isTemporaryEvent(ev Event, runID string) bool {
	if runID == "" {
		return false
	}
	runComment := "nftracepath:" + runID
	runPrefix := "NFTP:" + runID
	return strings.Contains(ev.Raw, runComment) ||
		strings.Contains(ev.Raw, runPrefix) ||
		strings.Contains(ev.RuleRef.Rule, runComment) ||
		strings.Contains(ev.RuleRef.Table, "nftracepath_"+runID)
}

func isSystemEvent(ev Event) bool {
	if ev.RuleRef.Rule != "" {
		return true
	}
	switch ev.Kind {
	case "rule", "verdict":
		return ev.RuleRef.Table != "" || ev.RuleRef.Chain != ""
	}
	return false
}

func flowMatchesLog(line string, f Flow) bool {
	upper := strings.ToUpper(line)
	if !(strings.Contains(line, "SRC="+f.Src4()) &&
		strings.Contains(line, "DST="+f.Dst4()) &&
		strings.Contains(upper, "PROTO="+strings.ToUpper(string(f.Proto)))) {
		return false
	}
	if f.SrcPort > 0 && !strings.Contains(line, "SPT="+strconv.Itoa(f.SrcPort)) {
		return false
	}
	if f.DstPort > 0 && !strings.Contains(line, "DPT="+strconv.Itoa(f.DstPort)) {
		return false
	}
	return true
}

func flowMatchesNFTLine(line string, f Flow) bool {
	if !(strings.Contains(line, "ip saddr "+f.Src4()) &&
		strings.Contains(line, "ip daddr "+f.Dst4())) {
		return false
	}
	if f.SrcPort > 0 && !strings.Contains(line, string(f.Proto)+" sport "+strconv.Itoa(f.SrcPort)) {
		return false
	}
	if f.DstPort > 0 && !strings.Contains(line, string(f.Proto)+" dport "+strconv.Itoa(f.DstPort)) {
		return false
	}
	return true
}

func parseINOUT(line string) (string, string) {
	var inIface, outIface string
	for _, m := range iptablesKVPairRE.FindAllStringSubmatch(line, -1) {
		switch m[1] {
		case "IN":
			inIface = m[2]
		case "OUT":
			outIface = m[2]
		}
	}
	return inIface, outIface
}

func parseVerdict(rest string) string {
	m := nftVerdictRE.FindStringSubmatch(rest)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return strings.ToLower(m[1])
	}
	return strings.ToLower(m[2])
}

func parseIPTablesVerdict(ev Event) string {
	if ev.Kind == "policy" {
		return "policy"
	}
	if ev.RuleRef.Rule == "" {
		return ""
	}
	fields := strings.Fields(ev.RuleRef.Rule)
	for i, field := range fields {
		if field == "-j" && i+1 < len(fields) {
			return strings.ToLower(fields[i+1])
		}
	}
	return ""
}

func parseFinalHint(s string) string {
	switch {
	case strings.Contains(s, ":final-input"):
		return "input"
	case strings.Contains(s, ":final-forward"):
		return "forward"
	case strings.Contains(s, ":final-postrouting"):
		return "postrouting"
	case strings.Contains(s, "final_input"):
		return "input"
	case strings.Contains(s, "final_forward"):
		return "forward"
	case strings.Contains(s, "final_postrouting"):
		return "postrouting"
	default:
		return ""
	}
}

func parseIPTablesFinalHint(line string) string {
	switch {
	case strings.Contains(line, ":IN "):
		return "input"
	case strings.Contains(line, ":FWD "):
		return "forward"
	case strings.Contains(line, ":POST "):
		return "postrouting"
	default:
		return ""
	}
}

func parseQuotedIface(rest, key string) string {
	needle := key + ` "`
	idx := strings.Index(rest, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.IndexByte(rest[start:], '"')
	if end < 0 {
		return ""
	}
	return rest[start : start+end]
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			return m[i]
		}
	}
	return ""
}

func nftRuleKey(family, table, chain, handle string) string {
	return family + "/" + table + "/" + chain + "/" + handle
}

func iptablesRuleKey(table, chain string, number int) string {
	return table + "/" + chain + "/" + strconv.Itoa(number)
}
