package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssm/internal/ssh"
)

func TestRequestV1PublishedSchemaIncludesStrictGet(t *testing.T) {
	path := filepath.Join("..", "..", "skills", "agent-ssm", "references", "request-v1.schema.json")
	data, err := os.ReadFile(path) //nolint:gosec // repository-owned public schema fixture
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("published request schema is invalid JSON: %v", err)
	}
	text := string(data)
	for _, fragment := range []string{
		`"get"`,
		`"required": ["alias", "local_path", "remote_path"]`,
		`"required": ["resume"]`,
		`"required": ["dir_mode"]`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("published request schema missing get contract fragment %s", fragment)
		}
	}
}

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

func TestLoadAgentPutRequestResumeV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "put.json")
	body := `{"version":1,"op":"put","alias":"prod","local_path":"/secure/artifact","remote_path":"/srv/artifact","resume":"v1","sha256":true,"timeout":"2m"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	req, err := loadAgentRequest([]string{"--file", path})
	if err != nil {
		t.Fatal(err)
	}
	if req.Op != "put" || req.Resume != "v1" || !req.SHA256 || req.LocalPath == "" || req.RemotePath == "" {
		t.Fatalf("put request = %+v", req)
	}
}

func TestRequestRunSpecStdinFile(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "in.txt")
	script := filepath.Join(dir, "s.sh")
	for _, path := range []string{payload, script} {
		if err := os.WriteFile(path, []byte("true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", Argv: []string{"cat"}, StdinFile: payload})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Stdin != ssh.StdinForward || spec.StdinFile != payload {
		t.Fatalf("Stdin=%v StdinFile=%q", spec.Stdin, spec.StdinFile)
	}
	plain, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", Argv: []string{"cat"}})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Stdin != ssh.StdinDefault || plain.StdinFile != "" {
		t.Fatalf("default request Stdin=%v StdinFile=%q", plain.Stdin, plain.StdinFile)
	}
	fromStdin, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", Argv: []string{"cat"}, FromStdin: true})
	if err != nil {
		t.Fatal(err)
	}
	if fromStdin.Stdin != ssh.StdinDisable {
		t.Fatalf("request read from stdin must not forward stdin, got %v", fromStdin.Stdin)
	}
	for name, req := range map[string]agentRequest{
		"with script_file": {Version: 1, Op: "run", Alias: "prod", ScriptFile: script, StdinFile: payload},
		"missing file":     {Version: 1, Op: "run", Alias: "prod", Argv: []string{"cat"}, StdinFile: filepath.Join(dir, "absent")},
	} {
		if _, err := requestRunSpec(req); err == nil {
			t.Errorf("%s: accepted stdin_file request", name)
		}
	}
}

func TestLoadAgentRequestAcceptsStdinFileAndRejectsItOutsideRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.json")
	body := `{"version":1,"op":"run","alias":"prod","argv":["cat"],"stdin_file":"in.txt"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err := loadAgentRequest([]string{"--file", path})
	if err != nil {
		t.Fatal(err)
	}
	if req.StdinFile != "in.txt" || req.FromStdin {
		t.Fatalf("request = %+v", req)
	}
	if !hasRunRequestFields(agentRequest{StdinFile: "in.txt"}) {
		t.Fatal("stdin_file must count as a run field so check/doctor/host reject it")
	}
}

func TestRequestV1PublishedSchemaDeclaresStdinFile(t *testing.T) {
	path := filepath.Join("..", "..", "skills", "agent-ssm", "references", "request-v1.schema.json")
	data, err := os.ReadFile(path) //nolint:gosec // repository-owned public schema fixture
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, fragment := range []string{
		`"stdin_file": {"type": "string", "minLength": 1}`,
		`{"required": ["shell_command"]}, {"required": ["stdin_file"]}]}}`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("published request schema missing stdin_file fragment %s", fragment)
		}
	}
	if got := strings.Count(text, `{"required": ["stdin_file"]}`); got != 3 {
		t.Errorf("stdin_file exclusions = %d, want 3 (script_file run, put, get)", got)
	}
}

func TestRequestV1PublishedSchemaDeclaresTransfer(t *testing.T) {
	path := filepath.Join("..", "..", "skills", "agent-ssm", "references", "request-v1.schema.json")
	data, err := os.ReadFile(path) //nolint:gosec // repository-owned public schema fixture
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       struct {
			Host struct {
				Additional bool                       `json:"additionalProperties"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"host"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if _, ok := schema.Properties["transfer"]; !ok {
		t.Error("schema lacks top-level transfer")
	}
	if _, ok := schema.Defs.Host.Properties["transfer"]; !ok || schema.Defs.Host.Additional {
		t.Error("schema host object lacks transfer or allows additional properties")
	}
	text := string(data)
	if !strings.Contains(text, `{"required": ["transfer"]}]},
        "oneOf"`) {
		t.Error("run/plan must reject transfer")
	}
	if !strings.Contains(text, `"then": {"not": {"required": ["transfer"]}}`) {
		t.Error("non-transfer ops must reject transfer")
	}
}
