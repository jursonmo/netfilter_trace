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

func mustFlow(t *testing.T, proto, src string, sport int, dst string, dport int, inIface string) Flow {
	t.Helper()
	flow, err := NewFlow(proto, src, sport, dst, dport, inIface)
	if err != nil {
		t.Fatal(err)
	}
	return flow
}
