//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/config"
)

// RunWithoutHomeWithEnv keeps the compiled CLI isolated while allowing this
// test to verify the startup path with HOME and USERPROFILE absent.
func (h *compiledCLIHarness) RunWithoutHomeWithEnv(t *testing.T, executable string, env map[string]string, args ...string) compiledCLIResult {
	t.Helper()
	overrides := make(map[string]string, len(env)+1)
	for key, value := range env {
		overrides[key] = value
	}
	if _, exists := overrides["SSM_MASTER_PASS_FILE"]; !exists {
		overrides["SSM_MASTER_PASS_FILE"] = h.passPath
	}
	path, ok := h.paths[executable]
	if !ok {
		t.Fatalf("unknown compiled CLI executable name %q", executable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), compiledCLISubprocessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // executable is selected from test-owned compiled binary paths
	cmd.Args[0] = executable
	cmd.Dir = h.temp
	cmd.Env = compiledEnvironmentWithoutHome(h.home, h.temp, overrides)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("compiled %s exceeded subprocess deadline %s", executable, compiledCLISubprocessTimeout)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run compiled %s: %v", executable, err)
		}
		return compiledCLIResult{ProcessExit: exitErr.ExitCode(), Stdout: stdout.String(), Stderr: stderr.String()}
	}
	return compiledCLIResult{Stdout: stdout.String(), Stderr: stderr.String()}
}

func compiledEnvironmentWithoutHome(home, temp string, overrides map[string]string) []string {
	env := isolatedCompiledCLIEnvironmentWith(home, temp, overrides)
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == "HOME" || key == "USERPROFILE" {
			continue
		}
		if key == "SSM_CONFIG_DIR" {
			if _, overridden := overrides[key]; !overridden {
				continue
			}
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func TestCompiledHomeUnavailable(t *testing.T) {
	cli := newCompiledCLIHarness(t)

	t.Run("fails without home or config override", func(t *testing.T) {
		result := cli.RunWithoutHomeWithEnv(t, "sshctl", nil, "--json", "list")
		if result.ProcessExit != 1 {
			t.Fatalf("process exit = %d, want 1; output=%s", result.ProcessExit, compiledOutputIdentity(result))
		}
		var document map[string]any
		decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(result.Stdout)))
		if err := decoder.Decode(&document); err != nil {
			t.Fatalf("decode failure JSON: %v; output=%q", err, result.Stdout)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			t.Fatalf("failure stdout has more than one JSON document: %v", err)
		}
		for field, want := range map[string]any{
			"error":   "internal",
			"hint":    "set HOME or SSM_CONFIG_DIR",
			"message": "configuration directory unavailable",
		} {
			if document[field] != want {
				t.Fatalf("failure %s = %v, want %v; output=%q", field, document[field], want, result.Stdout)
			}
		}
		entries, err := os.ReadDir(cli.temp)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("compiled CLI created files in cwd: %v", entries)
		}
	})

	for _, args := range [][]string{{"--version"}, {"--help"}} {
		args := args
		name := strings.TrimPrefix(args[0], "--")
		t.Run(name+" remains available", func(t *testing.T) {
			result := cli.RunWithoutHomeWithEnv(t, "sshctl", nil, args...)
			if result.ProcessExit != 0 || strings.Contains(result.Stdout, "configuration directory unavailable") {
				t.Fatalf("%s result = %s", args[0], compiledOutputIdentity(result))
			}
		})
	}

	t.Run("works with config override", func(t *testing.T) {
		cli.SaveVault(t, &config.Vault{})
		result := cli.RunWithoutHomeWithEnv(t, "sshctl", map[string]string{
			"SSM_CONFIG_DIR": filepath.Join(cli.home, ".config", "ssm"),
		}, "--json", "list")
		if result.ProcessExit != 0 {
			t.Fatalf("process exit = %d, want 0; output=%s", result.ProcessExit, compiledOutputIdentity(result))
		}
		if !json.Valid([]byte(strings.TrimSpace(result.Stdout))) {
			t.Fatalf("config override did not return JSON: %q", result.Stdout)
		}
	})
}
