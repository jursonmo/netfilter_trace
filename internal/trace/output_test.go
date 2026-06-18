package trace

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteHumanPrintsDebugRules(t *testing.T) {
	result := Result{
		RunID:      "abcd1234",
		Flow:       mustFlow(t, "udp", "192.0.2.10", 12345, "198.51.100.20", 53, ""),
		Backend:    BackendIPTables,
		Mode:       ModeListen,
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Outcome:    OutcomeTimeout,
		DebugRules: []string{
			"iptables -t raw -I OUTPUT 1 -p udp -j TRACE",
			"iptables -t mangle -A POSTROUTING -p udp -j LOG --log-prefix NFTP:abcd1234:POST",
		},
	}
	var buf bytes.Buffer
	if err := WriteHuman(&buf, result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Debug rules:", "iptables -t raw -I OUTPUT 1", "iptables -t mangle -A POSTROUTING"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteHumanPrintsRuleOrigin(t *testing.T) {
	result := Result{
		RunID:      "abcd1234",
		Flow:       mustFlow(t, "tcp", "192.0.2.10", 12345, "198.51.100.20", 443, ""),
		Backend:    BackendIPTables,
		Mode:       ModeListen,
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Outcome:    OutcomeDrop,
		Events: []Event{
			{
				Kind:    "rule",
				Verdict: "trace",
				RuleRef: RuleRef{
					Table:  "raw",
					Chain:  "PREROUTING",
					Number: 1,
					Origin: "temporary",
					Rule:   "-A PREROUTING -m comment --comment nftracepath:abcd1234:trace-prerouting -j TRACE",
				},
			},
			{
				Kind:    "rule",
				Verdict: "drop",
				RuleRef: RuleRef{
					Table:  "filter",
					Chain:  "INPUT",
					Number: 1,
					Origin: "system",
					Rule:   "-A INPUT -j DROP",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteHuman(&buf, result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"origin", "temporary", "system"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteHumanDoesNotPrintPolicyAsRuleNumber(t *testing.T) {
	result := Result{
		RunID:      "bf6f8369",
		Flow:       mustFlow(t, "tcp", "192.168.244.129", 0, "2.2.2.2", 88, ""),
		Backend:    BackendIPTables,
		Mode:       ModeListen,
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Outcome:    OutcomeEgress,
		Events: []Event{
			{
				Kind:     "policy",
				Verdict:  "policy",
				OutIface: "ens160",
				RuleRef: RuleRef{
					Table:  "mangle",
					Chain:  "OUTPUT",
					Origin: "policy",
				},
				Raw: "TRACE: mangle:OUTPUT:policy:1 IN= OUT=ens160 SRC=192.168.244.129 DST=2.2.2.2 PROTO=TCP DPT=88",
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteHuman(&buf, result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "OUTPUT:1") {
		t.Fatalf("policy event should not be printed as a numbered rule:\n%s", out)
	}
	for _, want := range []string{"policy", "mangle", "OUTPUT"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q:\n%s", want, out)
		}
	}
}

func mustFlow(t *testing.T, proto, src string, sport int, dst string, dport int, inIface string) Flow {
	t.Helper()
	flow, err := NewFlow(proto, src, sport, dst, dport, inIface)
	if err != nil {
		t.Fatal(err)
	}
	return flow
}
