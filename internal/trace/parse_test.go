package trace

import "testing"

func TestParseNFTRulesetAndTraceLine(t *testing.T) {
	ruleset := `
table inet filter {
	chain input {
		tcp dport 22 accept # handle 7
		ip saddr 192.0.2.10 counter comment "nftracepath:abcd1234:final-input" # handle 8
	}
}
`
	rules := parseNFTRuleset(ruleset)
	if got := rules[nftRuleKey("inet", "filter", "input", "7")]; got != `tcp dport 22 accept # handle 7` {
		t.Fatalf("unexpected mapped rule: %q", got)
	}

	ev, ok := parseNFTTraceLine(`trace id 1234 inet filter input rule tcp dport 22 accept # handle 7 (verdict accept)`, rules)
	if !ok {
		t.Fatal("expected nft trace line to parse")
	}
	if ev.TraceID != "1234" || ev.RuleRef.Handle != "7" || ev.Verdict != "accept" || ev.RuleRef.Rule == "" {
		t.Fatalf("unexpected event: %#v", ev)
	}

	ev, ok = parseNFTTraceLine(`trace id 1234 inet filter input packet: iif "eth0" oif "eth1" ip saddr 192.0.2.10 ip daddr 198.51.100.20 tcp sport 12345 tcp dport 443`, rules)
	if !ok {
		t.Fatal("expected nft packet line to parse")
	}
	if ev.InIface != "eth0" || ev.OutIface != "eth1" {
		t.Fatalf("unexpected interfaces: %#v", ev)
	}
	flow, err := NewFlow("tcp", "192.0.2.10", 12345, "198.51.100.20", 443, "")
	if err != nil {
		t.Fatal(err)
	}
	if !flowMatchesNFTLine(ev.Raw, flow) {
		t.Fatalf("expected nft packet line to match flow: %s", ev.Raw)
	}

	ev, ok = parseNFTTraceLine(`trace id 1234 inet nftracepath_abcd final_postrouting packet: oif "r1" ip saddr 192.0.2.10 ip daddr 198.51.100.20 tcp sport 12345 tcp dport 443`, rules)
	if !ok {
		t.Fatal("expected nft final postrouting packet line to parse")
	}
	if ev.FinalHint != "postrouting" || ev.OutIface != "r1" {
		t.Fatalf("unexpected final hint: %#v", ev)
	}
}

func TestAnnotateNFTEventRuleOrigin(t *testing.T) {
	rules := parseNFTRuleset(`
table inet filter {
	chain input {
		tcp dport 22 accept # handle 7
	}
}
table inet nftracepath_abcd1234 {
	chain final_input {
		ip saddr 192.0.2.10 counter comment "nftracepath:abcd1234:final-input" # handle 8
	}
}
`)
	systemEv, ok := parseNFTTraceLine(`trace id 1 inet filter input rule tcp dport 22 accept # handle 7 (verdict accept)`, rules)
	if !ok {
		t.Fatal("expected system nft event to parse")
	}
	annotateRuleOrigin(&systemEv, "abcd1234")
	if systemEv.RuleRef.Origin != "system" {
		t.Fatalf("expected system origin, got %#v", systemEv.RuleRef)
	}

	tempEv, ok := parseNFTTraceLine(`trace id 1 inet nftracepath_abcd1234 final_input rule ip saddr 192.0.2.10 counter comment "nftracepath:abcd1234:final-input" # handle 8`, rules)
	if !ok {
		t.Fatal("expected temporary nft event to parse")
	}
	annotateRuleOrigin(&tempEv, "abcd1234")
	if tempEv.RuleRef.Origin != "temporary" {
		t.Fatalf("expected temporary origin, got %#v", tempEv.RuleRef)
	}
}

func TestParseIPTablesSaveAndLogLine(t *testing.T) {
	snapshot := `
*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 192.0.2.10/32 -d 198.51.100.20/32 -p tcp -m tcp --sport 12345 --dport 443 -j DROP
COMMIT
`
	rules := parseIPTablesSave(snapshot)
	if got := rules[iptablesRuleKey("filter", "INPUT", 1)]; got == "" {
		t.Fatal("expected filter INPUT rule 1 to be mapped")
	}
	line := `TRACE: filter:INPUT:rule:1 IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 LEN=60 PROTO=TCP SPT=12345 DPT=443`
	ev, ok := parseIPTablesLogLine(line, rules)
	if !ok {
		t.Fatal("expected iptables trace line to parse")
	}
	if ev.RuleRef.Table != "filter" || ev.RuleRef.Chain != "INPUT" || ev.RuleRef.Number != 1 || ev.Verdict != "drop" {
		t.Fatalf("unexpected event: %#v", ev)
	}
	if ev.InIface != "eth0" || ev.OutIface != "" {
		t.Fatalf("unexpected interfaces: %#v", ev)
	}
	flow, err := NewFlow("tcp", "192.0.2.10", 12345, "198.51.100.20", 443, "")
	if err != nil {
		t.Fatal(err)
	}
	if !flowMatchesLog(line, flow) {
		t.Fatalf("expected iptables log line to match flow: %s", line)
	}
}

func TestAnnotateIPTablesEventRuleOrigin(t *testing.T) {
	rules := parseIPTablesSave(`
*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -s 192.0.2.10/32 -d 198.51.100.20/32 -p tcp -m comment --comment nftracepath:abcd1234:trace-prerouting -j TRACE
COMMIT
*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 192.0.2.10/32 -d 198.51.100.20/32 -p tcp -j DROP
COMMIT
`)
	tempEv, ok := parseIPTablesLogLine(`TRACE: raw:PREROUTING:rule:1 IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 PROTO=TCP SPT=12345 DPT=443`, rules)
	if !ok {
		t.Fatal("expected temporary iptables trace line to parse")
	}
	annotateRuleOrigin(&tempEv, "abcd1234")
	if tempEv.RuleRef.Origin != "temporary" {
		t.Fatalf("expected temporary origin, got %#v", tempEv.RuleRef)
	}

	systemEv, ok := parseIPTablesLogLine(`TRACE: filter:INPUT:rule:1 IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 PROTO=TCP SPT=12345 DPT=443`, rules)
	if !ok {
		t.Fatal("expected system iptables trace line to parse")
	}
	annotateRuleOrigin(&systemEv, "abcd1234")
	if systemEv.RuleRef.Origin != "system" {
		t.Fatalf("expected system origin, got %#v", systemEv.RuleRef)
	}

	logEv, ok := parseIPTablesLogLine(`NFTP:abcd1234:POST IN= OUT=eth1 SRC=192.0.2.10 DST=198.51.100.20 PROTO=UDP SPT=53000 DPT=53`, rules)
	if !ok {
		t.Fatal("expected temporary iptables log line to parse")
	}
	annotateRuleOrigin(&logEv, "abcd1234")
	if logEv.RuleRef.Origin != "temporary" {
		t.Fatalf("expected temporary log origin, got %#v", logEv.RuleRef)
	}
}

func TestParseIPTablesPolicyDoesNotMapRuleNumber(t *testing.T) {
	rules := parseIPTablesSave(`
*mangle
:OUTPUT ACCEPT [0:0]
-A OUTPUT -s 192.0.2.10/32 -d 198.51.100.20/32 -p tcp -j MARK --set-xmark 0x1/0xffffffff
COMMIT
`)
	line := `TRACE: mangle:OUTPUT:policy:1 IN= OUT=ens160 SRC=192.168.244.129 DST=2.2.2.2 LEN=60 TOS=0x10 PROTO=TCP DPT=88`
	ev, ok := parseIPTablesLogLine(line, rules)
	if !ok {
		t.Fatal("expected iptables policy trace line to parse")
	}
	annotateRuleOrigin(&ev, "bf6f8369")
	if ev.Kind != "policy" || ev.RuleRef.Number != 0 || ev.RuleRef.Rule != "" || ev.RuleRef.Origin != "policy" {
		t.Fatalf("policy event should not be treated as a rule hit: %#v", ev)
	}
}

func TestFlowMatchesLogWithOmittedPorts(t *testing.T) {
	flow, err := NewFlow("udp", "192.0.2.10", 0, "198.51.100.20", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	line := `TRACE: raw:PREROUTING:policy:1 IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 PROTO=UDP SPT=12345 DPT=53`
	if !flowMatchesLog(line, flow) {
		t.Fatalf("expected omitted-port flow to match log line: %s", line)
	}
	flow.DstPort = 443
	if flowMatchesLog(line, flow) {
		t.Fatalf("expected mismatched specified destination port not to match: %s", line)
	}
}

func TestFlowMatchesNFTLineWithOmittedPorts(t *testing.T) {
	flow, err := NewFlow("tcp", "192.0.2.10", 0, "198.51.100.20", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	line := `trace id abcd inet filter input packet: iif "eth0" ip saddr 192.0.2.10 ip daddr 198.51.100.20 tcp sport 12345 tcp dport 443`
	if !flowMatchesNFTLine(line, flow) {
		t.Fatalf("expected omitted-port flow to match nft line: %s", line)
	}
	flow.SrcPort = 53000
	if flowMatchesNFTLine(line, flow) {
		t.Fatalf("expected mismatched specified source port not to match: %s", line)
	}
}

func TestParseIPTablesFinalLog(t *testing.T) {
	ev, ok := parseIPTablesLogLine(`NFTP:abcd1234:POST IN= OUT=eth1 SRC=192.0.2.10 DST=198.51.100.20 PROTO=UDP SPT=53000 DPT=53`, nil)
	if !ok {
		t.Fatal("expected final log line to parse")
	}
	if ev.FinalHint != "postrouting" || ev.OutIface != "eth1" {
		t.Fatalf("unexpected event: %#v", ev)
	}
}

func TestIPTablesInputAcceptInfersLocalOutcome(t *testing.T) {
	rules := parseIPTablesSave(`
*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 198.18.193.2/32 -d 198.18.193.1/32 -p udp -m udp --sport 43101 --dport 53101 -m comment --comment "nftp-host-smoke:142835" -j ACCEPT
COMMIT
`)
	ev, ok := parseIPTablesLogLine(`TRACE: filter:INPUT:rule:1 IN=br-nftp-142835 OUT= PHYSIN=vh142835 SRC=198.18.193.2 DST=198.18.193.1 PROTO=UDP SPT=43101 DPT=53101`, rules)
	if !ok {
		t.Fatal("expected iptables input accept trace line to parse")
	}
	annotateRuleOrigin(&ev, "abcd1234")
	result := baseResult(RunConfig{}, BackendIPTables)
	applyEventOutcome(&result, ev)
	if result.Outcome != OutcomeLocal {
		t.Fatalf("expected input accept to infer local outcome, got %s from %#v", result.Outcome, ev)
	}
}
