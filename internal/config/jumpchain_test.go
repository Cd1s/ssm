package config

import (
	"errors"
	"fmt"
	"testing"
)

func chainVault(links map[string]string, names ...string) *Vault {
	v := &Vault{}
	for _, name := range names {
		v.Connections = append(v.Connections, Connection{Name: name, Host: name + ".example.test", User: "u", Password: "p", ProxyJump: links[name]})
	}
	return v
}

func names(chain []Connection) []string {
	out := make([]string, len(chain))
	for i, c := range chain {
		out[i] = c.Name
	}
	return out
}

func TestResolveJumpChainOrdersJumpsBeforeTarget(t *testing.T) {
	v := chainVault(map[string]string{"c": "b", "b": "a"}, "a", "b", "c")
	chain, err := ResolveJumpChain(v, v.Connections[2])
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(chain)); got != "[a b c]" {
		t.Fatalf("chain = %s, want [a b c]", got)
	}
	plain, err := ResolveJumpChain(v, v.Connections[0])
	if err != nil || len(plain) != 1 || plain[0].Name != "a" {
		t.Fatalf("no proxy_jump chain = %v err=%v", names(plain), err)
	}
}

func TestResolveJumpChainRejectsCyclesDepthAndMissing(t *testing.T) {
	cycle := chainVault(map[string]string{"a": "b", "b": "a"}, "a", "b")
	self := chainVault(map[string]string{"a": "a"}, "a")
	longer := chainVault(map[string]string{"h6": "h5", "h5": "h4", "h4": "h3", "h3": "h2", "h2": "h1", "h1": "h0"}, "h0", "h1", "h2", "h3", "h4", "h5", "h6")
	exact := chainVault(map[string]string{"h5": "h4", "h4": "h3", "h3": "h2", "h2": "h1", "h1": "h0"}, "h0", "h1", "h2", "h3", "h4", "h5")
	missing := chainVault(map[string]string{"a": "ghost"}, "a")
	tests := []struct {
		name   string
		vault  *Vault
		target string
		reason string
	}{
		{"cycle", cycle, "a", JumpCycle},
		{"self", self, "a", JumpCycle},
		{"six jump hosts", longer, "h6", JumpDepth},
		{"five jump hosts", exact, "h5", ""},
		{"missing", missing, "a", JumpMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target Connection
			for _, c := range tt.vault.Connections {
				if c.Name == tt.target {
					target = c
				}
			}
			_, err := ResolveJumpChain(tt.vault, target)
			if tt.reason == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			var chainErr *JumpChainError
			if !errors.As(err, &chainErr) || chainErr.Reason != tt.reason {
				t.Fatalf("err = %v, want reason %s", err, tt.reason)
			}
		})
	}
}

func TestResolveJumpChainAppliesRedirects(t *testing.T) {
	t.Setenv("SSM_CONFIG_DIR", t.TempDir())
	if err := SaveRedirects(Redirects{"old-jump": "real-jump"}); err != nil {
		t.Fatal(err)
	}
	v := chainVault(map[string]string{"t": "old-jump"}, "real-jump", "t")
	chain, err := ResolveJumpChain(v, v.Connections[1])
	if err != nil || fmt.Sprint(names(chain)) != "[real-jump t]" {
		t.Fatalf("chain = %v err=%v, want the redirect target", names(chain), err)
	}
}
