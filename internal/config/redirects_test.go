package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAliasRedirect(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, dir)
	// Dir() uses home/.config/ssm
	if err := os.MkdirAll(filepath.Join(dir, ".config", "ssm"), 0700); err != nil {
		t.Fatal(err)
	}
	r := Redirects{"old-name": "limee-hk"}
	if err := SaveRedirects(r); err != nil {
		t.Fatal(err)
	}
	v := &Vault{Connections: []Connection{
		{Name: "limee-hk", Host: "1.2.3.4", Port: 22, User: "root"},
	}}
	c, resolved, ok := ResolveAlias(v, "old-name")
	if !ok || resolved != "limee-hk" || c.Host != "1.2.3.4" {
		t.Fatalf("got ok=%v resolved=%q host=%q", ok, resolved, c.Host)
	}
}

func TestResolveAliasCycle(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, dir)
	_ = os.MkdirAll(filepath.Join(dir, ".config", "ssm"), 0700)
	_ = SaveRedirects(Redirects{"a": "b", "b": "a"})
	v := &Vault{Connections: []Connection{{Name: "a", Host: "h", User: "u"}}}
	_, _, ok := ResolveAlias(v, "a")
	if ok {
		t.Fatal("expected cycle to fail resolution")
	}
}

func TestMatchAliasesGlob(t *testing.T) {
	v := &Vault{Connections: []Connection{
		{Name: "limee-hk"},
		{Name: "limee-sg"},
		{Name: "aws-sg"},
	}}
	got, err := MatchAliases(v, []string{"limee-*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %#v", got)
	}
}
