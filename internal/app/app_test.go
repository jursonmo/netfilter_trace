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
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated command missing %q:\n%s", want, got)
		}
	}
}
