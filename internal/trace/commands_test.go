package trace

import (
	"testing"
	"time"
)

func TestNFTSetupAndCleanupScripts(t *testing.T) {
	flow, err := NewFlow("tcp", "192.0.2.10", 12345, "198.51.100.20", 443, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testRunConfig(flow)
	setup := nftSetupScript(cfg, "nftracepath_abcd1234", "abcd1234")
	for _, want := range []string{
		"add table inet nftracepath_abcd1234",
		"trace_prerouting",
		`iifname "eth0"`,
		"limit rate 10/second burst 20 packets",
		"meta nftrace set 1",
		`comment "nftracepath:abcd1234:final-postrouting"`,
	} {
		if !contains(setup, want) {
			t.Fatalf("nft setup script does not contain %q:\n%s", want, setup)
		}
	}
	if contains(setup, "trace_output") {
		t.Fatalf("nft setup script should not install output trace when in-iface is set:\n%s", setup)
	}
	cleanup := nftCleanupScript("nftracepath_abcd1234")
	if !contains(cleanup, "nft delete table inet nftracepath_abcd1234") || !contains(cleanup, "|| true") {
		t.Fatalf("unexpected nft cleanup script: %s", cleanup)
	}
}

func TestNFTSetupIncludesOutputTraceWithoutInIface(t *testing.T) {
	flow, err := NewFlow("tcp", "192.0.2.10", 12345, "198.51.100.20", 443, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testRunConfig(flow)
	setup := nftSetupScript(cfg, "nftracepath_abcd1234", "abcd1234")
	for _, want := range []string{
		"add chain inet nftracepath_abcd1234 trace_output",
		"add rule inet nftracepath_abcd1234 trace_output",
		`comment "nftracepath:abcd1234:trace-output"`,
	} {
		if !contains(setup, want) {
			t.Fatalf("nft setup script does not contain %q:\n%s", want, setup)
		}
	}
}

func TestIPTablesSetupAndCleanupScripts(t *testing.T) {
	flow, err := NewFlow("udp", "192.0.2.10", 53000, "198.51.100.53", 53, "wan0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testRunConfig(flow)
	setup := iptablesSetupScript(cfg, "abcd1234")
	for _, want := range []string{
		"iptables -t raw -I PREROUTING 1",
		"-i wan0",
		"-m limit --limit 10/second --limit-burst 20",
		"--comment nftracepath:abcd1234:trace-prerouting",
		"-j TRACE",
		"--log-prefix 'NFTP:abcd1234:POST '",
	} {
		if !contains(setup, want) {
			t.Fatalf("iptables setup script does not contain %q:\n%s", want, setup)
		}
	}
	for _, unwanted := range []string{
		"iptables -t raw -I OUTPUT 1",
		"--comment nftracepath:abcd1234:trace-output",
	} {
		if contains(setup, unwanted) {
			t.Fatalf("iptables setup script should not contain %q when in-iface is set:\n%s", unwanted, setup)
		}
	}
	cleanup := iptablesCleanupScript(cfg, "abcd1234")
	for _, want := range []string{
		"iptables -t raw -D PREROUTING",
		"--comment nftracepath:abcd1234:trace-prerouting",
		"|| true",
	} {
		if !contains(cleanup, want) {
			t.Fatalf("iptables cleanup script does not contain %q:\n%s", want, cleanup)
		}
	}
	if contains(cleanup, "iptables -t raw -D OUTPUT") {
		t.Fatalf("iptables cleanup script should not delete output trace when in-iface is set:\n%s", cleanup)
	}
}

func TestIPTablesMonitorScriptOnlyFollowsNewKernelLogs(t *testing.T) {
	script := iptablesMonitorScript()
	for _, want := range []string{
		"journalctl -k -f -n 0 -o cat",
		"dmesg -W",
	} {
		if !contains(script, want) {
			t.Fatalf("iptables monitor script does not contain %q:\n%s", want, script)
		}
	}
	if contains(script, "journalctl -kf -o cat") {
		t.Fatalf("iptables monitor script can replay journal tail:\n%s", script)
	}
}

func TestIPTablesSetupAndCleanupIncludeOutputTraceWithoutInIface(t *testing.T) {
	flow, err := NewFlow("udp", "192.0.2.10", 53000, "198.51.100.53", 53, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testRunConfig(flow)
	setup := iptablesSetupScript(cfg, "abcd1234")
	for _, want := range []string{
		"iptables -t raw -I OUTPUT 1",
		"--comment nftracepath:abcd1234:trace-output",
		"-j TRACE",
	} {
		if !contains(setup, want) {
			t.Fatalf("iptables setup script does not contain %q:\n%s", want, setup)
		}
	}
	cleanup := iptablesCleanupScript(cfg, "abcd1234")
	for _, want := range []string{
		"iptables -t raw -D OUTPUT",
		"--comment nftracepath:abcd1234:trace-output",
	} {
		if !contains(cleanup, want) {
			t.Fatalf("iptables cleanup script does not contain %q:\n%s", want, cleanup)
		}
	}
}

func TestSetupScriptsOmitUnspecifiedPorts(t *testing.T) {
	flow, err := NewFlow("udp", "192.0.2.10", 0, "198.51.100.53", 0, "wan0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testRunConfig(flow)
	cfg.AllowBroadMatch = true
	nft := nftSetupScript(cfg, "nftracepath_abcd1234", "abcd1234")
	for _, unwanted := range []string{"udp sport", "udp dport"} {
		if contains(nft, unwanted) {
			t.Fatalf("nft setup script unexpectedly contains %q:\n%s", unwanted, nft)
		}
	}
	iptables := iptablesSetupScript(cfg, "abcd1234")
	for _, unwanted := range []string{"--sport", "--dport"} {
		if contains(iptables, unwanted) {
			t.Fatalf("iptables setup script unexpectedly contains %q:\n%s", unwanted, iptables)
		}
	}
}

func testRunConfig(flow Flow) RunConfig {
	return RunConfig{
		Flow:            flow,
		Mode:            ModeListen,
		Backend:         BackendAuto,
		Target:          TargetConfig{Kind: TargetLocal},
		Timeout:         time.Second,
		MaxEvents:       DefaultMaxEvents,
		TraceLimit:      DefaultTraceLimit,
		TraceLimitBurst: DefaultTraceLimitBurst,
		AllowBroadMatch: false,
	}
}
