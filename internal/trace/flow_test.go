package trace

import (
	"testing"
	"time"
)

func TestNewFlowValidation(t *testing.T) {
	flow, err := NewFlow("TCP", "192.0.2.10", 12345, "198.51.100.20", 443, "eth0")
	if err != nil {
		t.Fatalf("NewFlow returned error: %v", err)
	}
	if flow.Proto != ProtoTCP || flow.Src4() != "192.0.2.10" || flow.Dst4() != "198.51.100.20" || flow.InIface != "eth0" {
		t.Fatalf("unexpected flow: %#v", flow)
	}

	if _, err := NewFlow("icmp", "192.0.2.10", 12345, "198.51.100.20", 443, ""); err == nil {
		t.Fatal("expected unsupported protocol to fail")
	}
	if _, err := NewFlow("tcp", "not-ip", 12345, "198.51.100.20", 443, ""); err == nil {
		t.Fatal("expected invalid source IP to fail")
	}
	if _, err := NewFlow("udp", "192.0.2.10", -1, "198.51.100.20", 443, ""); err == nil {
		t.Fatal("expected negative source port to fail")
	}
	if _, err := NewFlow("udp", "192.0.2.10", 0, "198.51.100.20", 0, ""); err != nil {
		t.Fatalf("expected omitted ports to be valid: %v", err)
	}
	if _, err := NewFlow("udp", "192.0.2.10", 12345, "198.51.100.20", 443, "eth0;rm"); err == nil {
		t.Fatal("expected unsafe interface name to fail")
	}
}

func TestMatchBuildersOmitUnspecifiedPorts(t *testing.T) {
	flow, err := NewFlow("tcp", "192.0.2.10", 0, "198.51.100.20", 0, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	nft := nftMatch(flow, true)
	for _, want := range []string{`iifname "eth0"`, "ip saddr 192.0.2.10", "ip daddr 198.51.100.20", "meta l4proto tcp"} {
		if !contains(nft, want) {
			t.Fatalf("nft match %q does not contain %q", nft, want)
		}
	}
	for _, unwanted := range []string{"tcp sport", "tcp dport"} {
		if contains(nft, unwanted) {
			t.Fatalf("nft match %q unexpectedly contains %q", nft, unwanted)
		}
	}

	args := shellJoin(iptablesMatchArgs(flow, true))
	for _, unwanted := range []string{"--sport", "--dport"} {
		if contains(args, unwanted) {
			t.Fatalf("iptables args %q unexpectedly contain %q", args, unwanted)
		}
	}
}

func TestRunConfigRejectsBroadPortMatchUnlessAllowed(t *testing.T) {
	flow, err := NewFlow("udp", "192.0.2.10", 0, "198.51.100.20", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := RunConfig{
		Flow:            flow,
		Mode:            ModeListen,
		Backend:         BackendAuto,
		Target:          TargetConfig{Kind: TargetLocal},
		Timeout:         time.Second,
		MaxEvents:       DefaultMaxEvents,
		TraceLimit:      DefaultTraceLimit,
		TraceLimitBurst: DefaultTraceLimitBurst,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected broad match without allow flag to fail")
	}
	cfg.AllowBroadMatch = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected broad match with allow flag to pass: %v", err)
	}
}

func TestMatchBuilders(t *testing.T) {
	flow, err := NewFlow("udp", "192.0.2.10", 53000, "198.51.100.53", 53, "wan0")
	if err != nil {
		t.Fatal(err)
	}
	nft := nftMatch(flow, true)
	for _, want := range []string{`iifname "wan0"`, "ip saddr 192.0.2.10", "meta l4proto udp", "udp dport 53"} {
		if !contains(nft, want) {
			t.Fatalf("nft match %q does not contain %q", nft, want)
		}
	}
	args := iptablesMatchArgs(flow, true)
	joined := shellJoin(args)
	for _, want := range []string{"-p udp", "-s 192.0.2.10", "--sport 53000", "-i wan0"} {
		if !contains(joined, want) {
			t.Fatalf("iptables args %q do not contain %q", joined, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
