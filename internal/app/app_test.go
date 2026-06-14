package app

import (
	"strings"
	"testing"
	"time"

	"netfilter_trace/internal/trace"
)

func TestCommandLineForConfigIncludesInteractiveChoices(t *testing.T) {
	flow, err := trace.NewFlow("tcp", "192.0.2.10", 12345, "198.51.100.20", 443, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := trace.RunConfig{
		Flow:            flow,
		Mode:            trace.ModeListen,
		Backend:         trace.BackendNFT,
		Target:          trace.TargetConfig{Kind: trace.TargetLocal},
		Timeout:         30 * time.Second,
		MaxEvents:       trace.DefaultMaxEvents,
		TraceLimit:      trace.DefaultTraceLimit,
		TraceLimitBurst: trace.DefaultTraceLimitBurst,
	}
	got := commandLineForConfig(cfg)
	for _, want := range []string{
		"./nftracepath run",
		"--proto tcp",
		"--src 192.0.2.10",
		"--sport 12345",
		"--dst 198.51.100.20",
		"--dport 443",
		"--in-iface eth0",
		"--mode listen",
		"--backend nft",
		"--target local",
		"--timeout 30s",
		"--max-events 200",
		"--trace-limit 10/second",
		"--trace-limit-burst 20",
		"--allow-broad-match=false",
		"--debug=false",
		"--json=false",
		"--sudo=false",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated command missing %q:\n%s", want, got)
		}
	}
}

func TestCommandLineForSSHIncludesDefaultPortAndBooleans(t *testing.T) {
	flow, err := trace.NewFlow("udp", "192.0.2.10", 0, "198.51.100.20", 53, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := trace.RunConfig{
		Flow:            flow,
		Mode:            trace.ModeListen,
		Backend:         trace.BackendAuto,
		Target:          trace.TargetConfig{Kind: trace.TargetSSH, SSHHost: "192.168.4.24", SSHUser: "root", SSHPort: 22},
		Timeout:         30 * time.Second,
		MaxEvents:       trace.DefaultMaxEvents,
		TraceLimit:      trace.DefaultTraceLimit,
		TraceLimitBurst: trace.DefaultTraceLimitBurst,
		Debug:           true,
	}
	got := commandLineForConfig(cfg)
	for _, want := range []string{
		"--target ssh",
		"--ssh-host 192.168.4.24",
		"--ssh-user root",
		"--ssh-port 22",
		"--dport 53",
		"--allow-broad-match=false",
		"--debug=true",
		"--json=false",
		"--sudo=false",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated command missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "--sport") {
		t.Fatalf("generated command should omit unspecified source port:\n%s", got)
	}
}
