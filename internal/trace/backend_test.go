package trace

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type fakeExecutor struct {
	target    TargetConfig
	responses map[string]string
}

func (f fakeExecutor) Shell(_ context.Context, script string) (string, error) {
	for _, key := range []string{"nft --handle list ruleset", "iptables --version", "iptables-save", "id -u", "sudo -n true"} {
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
