package trace

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeExecutor struct {
	target    TargetConfig
	responses map[string]string
}

func (f fakeExecutor) Shell(_ context.Context, script string) (string, error) {
	for _, key := range []string{"nft --handle list ruleset", "iptables-legacy --version", "iptables-legacy-save", "iptables --version", "iptables-save", "id -u", "sudo -n true"} {
		if strings.Contains(script, key) {
			if value, ok := f.responses[key]; ok {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("unexpected command: %s", script)
}

func (f fakeExecutor) Stream(context.Context, string) (<-chan string, <-chan error, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

func (f fakeExecutor) Target() TargetConfig {
	return f.target
}

func TestSelectBackendPrefersLegacyIPTablesWithRulesOverEmptyNFT(t *testing.T) {
	exec := fakeExecutor{responses: map[string]string{
		"nft --handle list ruleset": "",
		"iptables --version":        "iptables v1.8.4 (legacy)\n",
		"iptables-save": `*filter
:INPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
`,
	}}
	selected, err := selectBackend(context.Background(), exec, RunConfig{
		Backend: BackendAuto,
		Target:  TargetConfig{Kind: TargetLocal},
	})
	if err != nil {
		t.Fatalf("selectBackend returned error: %v", err)
	}
	if selected.Name() != BackendIPTables {
		t.Fatalf("expected iptables backend, got %s", selected.Name())
	}
}

func TestSelectBackendUsesIPTablesLegacyRulesWhenDefaultIPTablesIsNFT(t *testing.T) {
	exec := fakeExecutor{responses: map[string]string{
		"nft --handle list ruleset": "",
		"iptables-legacy --version": "iptables v1.8.4 (legacy)\n",
		"iptables-legacy-save": `*mangle
:OUTPUT ACCEPT [0:0]
-A OUTPUT -d 2.2.2.2/32 -j ACCEPT
COMMIT
`,
		"iptables --version": "iptables v1.8.4 (nf_tables)\n",
		"iptables-save":      "*mangle\nCOMMIT\n",
	}}
	selected, err := selectBackend(context.Background(), exec, RunConfig{
		Backend: BackendAuto,
		Target:  TargetConfig{Kind: TargetLocal},
	})
	if err != nil {
		t.Fatalf("selectBackend returned error: %v", err)
	}
	if selected.Name() != BackendIPTables {
		t.Fatalf("expected iptables backend, got %s", selected.Name())
	}
}

func TestDetectIPTablesLegacyToolsPrefersExplicitLegacyCommand(t *testing.T) {
	exec := fakeExecutor{responses: map[string]string{
		"iptables-legacy --version": "iptables v1.8.4 (legacy)\n",
		"iptables-legacy-save": `*filter
:INPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
`,
		"iptables --version": "iptables v1.8.4 (nf_tables)\n",
		"iptables-save":      "*filter\nCOMMIT\n",
	}}
	tools, err := detectIPTablesLegacyTools(context.Background(), exec, false)
	if err != nil {
		t.Fatalf("detectIPTablesLegacyTools returned error: %v", err)
	}
	if tools.Command != "iptables-legacy" || tools.SaveCommand != "iptables-legacy-save" || tools.Rules != 1 {
		t.Fatalf("unexpected legacy tools: %#v", tools)
	}
}

func TestSelectBackendPrefersNFTWhenRulesetHasRulesAndIPTablesIsNotLegacy(t *testing.T) {
	exec := fakeExecutor{responses: map[string]string{
		"nft --handle list ruleset": `table inet filter {
	chain input {
		tcp dport 22 accept # handle 7
	}
}
`,
		"iptables --version": "iptables v1.8.4 (nf_tables)\n",
		"iptables-save": `*filter
:INPUT ACCEPT [0:0]
COMMIT
`,
	}}
	selected, err := selectBackend(context.Background(), exec, RunConfig{
		Backend: BackendAuto,
		Target:  TargetConfig{Kind: TargetLocal},
	})
	if err != nil {
		t.Fatalf("selectBackend returned error: %v", err)
	}
	if selected.Name() != BackendNFT {
		t.Fatalf("expected nft backend, got %s", selected.Name())
	}
}

func TestSelectBackendFallsBackToAvailableNFTWhenBothStacksEmpty(t *testing.T) {
	exec := fakeExecutor{responses: map[string]string{
		"nft --handle list ruleset": "",
		"iptables --version":        "iptables v1.8.4 (nf_tables)\n",
		"iptables-save": `*filter
:INPUT ACCEPT [0:0]
COMMIT
`,
	}}
	selected, err := selectBackend(context.Background(), exec, RunConfig{
		Backend: BackendAuto,
		Target:  TargetConfig{Kind: TargetLocal},
	})
	if err != nil {
		t.Fatalf("selectBackend returned error: %v", err)
	}
	if selected.Name() != BackendNFT {
		t.Fatalf("expected nft backend, got %s", selected.Name())
	}
}

func TestTerminalDrainArmsOnce(t *testing.T) {
	var drain terminalDrain
	defer drain.Stop()
	if drain.C != nil {
		t.Fatal("terminal drain should start disabled")
	}
	drain.Arm()
	first := drain.C
	if first == nil {
		t.Fatal("terminal drain should expose timer channel after arm")
	}
	drain.Arm()
	if drain.C != first {
		t.Fatal("terminal drain should not reset once armed")
	}
	select {
	case <-drain.C:
	case <-time.After(terminalDrainDuration + 500*time.Millisecond):
		t.Fatal("terminal drain did not fire")
	}
}
