package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadAgentRequestStrictSchema(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"version":1,"op":"run","alias":"prod","argv":["printf","%s","a b"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	req, err := loadAgentRequest([]string{"--file", valid})
	if err != nil {
		t.Fatal(err)
	}
	if req.Op != "run" || req.Alias != "prod" || !reflect.DeepEqual(req.Argv, []string{"printf", "%s", "a b"}) {
		t.Fatalf("request = %+v", req)
	}

	for name, body := range map[string]string{
		"unknown":  `{"version":1,"op":"run","alias":"prod","argv":["true"],"surprise":1}`,
		"trailing": `{"version":1,"op":"run","alias":"prod","argv":["true"]} {}`,
		"version":  `{"version":2,"op":"run","alias":"prod","argv":["true"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadAgentRequest([]string{"--file", path}); err == nil {
				t.Fatalf("accepted %s request", name)
			}
		})
	}
}

func TestLoadAgentRequestRejectsDuplicateInput(t *testing.T) {
	if _, err := loadAgentRequest([]string{"--file", "one.json", "--file", "two.json"}); err == nil {
		t.Fatal("accepted duplicate request inputs")
	}
}

func TestRequestRunSpecPreservesExactArgvAndFileSecret(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(secretPath, []byte("secret with ' quote\n"), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := requestRunSpec(agentRequest{
		Version: 1, Op: "run", Alias: "prod",
		Argv:        []string{"printf", "%s", "a b ' c"},
		SecretFiles: map[string]string{"TOKEN": secretPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Mode != "argv" || spec.Command != `'printf' '%s' 'a b '"'"' c'` {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.Secrets["TOKEN"] != "secret with ' quote" {
		t.Fatal("secret file was not loaded exactly")
	}
}

func TestRequestRunSpecRequiresExactlyOneSource(t *testing.T) {
	command := "true"
	for _, req := range []agentRequest{
		{Version: 1, Op: "run", Alias: "prod"},
		{Version: 1, Op: "run", Alias: "prod", Argv: []string{"true"}, ShellCommand: &command},
		{Version: 1, Op: "run", Alias: "prod", Argv: []string{}},
	} {
		if _, err := requestRunSpec(req); err == nil {
			t.Fatalf("accepted request %+v", req)
		}
	}
}

func TestRequestScriptDefaultsToPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deploy.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ntrue\n"), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", ScriptFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Mode != "script" || !spec.Preflight || len(spec.Scripts) != 1 {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestRequestHostMutationDefaultsToVerify(t *testing.T) {
	address, user, savedKey := "203.0.113.10", "root", "deploy"
	args, err := requestHostArgs(agentRequest{
		Version: 1, Op: "host.upsert", Alias: "prod",
		Host: &agentHostRequest{Address: &address, User: &user, SavedKey: &savedKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--verify") || !strings.Contains(joined, "--json") {
		t.Fatalf("host args = %v", args)
	}
}
