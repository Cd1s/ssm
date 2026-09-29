package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"ssm/internal/config"
)

// helpSubcommands lists every subcommand of each entrypoint. A new subcommand
// must be added here so its --help is proven side-effect free.
var helpSubcommands = map[string][]string{
	"sshctl": {
		"request", "sync", "pull", "push", "list", "host", "hosts", "host-key", "known-hosts",
		"run", "exec", "plan", "map", "check", "doctor", "put", "get", "redirect", "alias-link",
		"shell", "status",
	},
	"ssm": {
		"update", "host", "hosts", "remove", "keys", "list", "ls", "exec", "run", "plan", "map",
		"check", "doctor", "redirect", "alias-link", "put", "get", "import-json", "server",
		"register", "login", "logout", "push", "pull", "pull-if-changed", "remote-hash",
	},
}

// snapshotTree records every path under root with a content digest so a test
// can prove a command left the tree byte-identical.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			snapshot[relative] = "dir"
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // path is beneath the harness's isolated t.TempDir home
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		snapshot[relative] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return snapshot
}

func TestCompiledSubcommandHelpHasNoSideEffects(t *testing.T) {
	var requests atomic.Int64
	syncServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "help must not reach the sync server", http.StatusTeapot)
	}))
	t.Cleanup(syncServer.Close)

	cli := newCompiledCLIHarness(t)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: "alpha", Host: "192.0.2.1", Port: 22, User: "u", Password: "p"}}})
	cli.SaveCloud(t, syncServer.URL, "HELP_SIDE_EFFECT_TOKEN_CANARY")
	cli.SaveRemoteETag(t, "etag-before-help")
	configDir := filepath.Dir(cli.passPath)
	env := map[string]string{"SSM_CONFIG_DIR": configDir}
	before := snapshotTree(t, configDir)
	updateRequests := len(compiledUpdateServer.RequestPaths())

	for _, executable := range []string{"sshctl", "ssm"} {
		for _, command := range helpSubcommands[executable] {
			for _, form := range [][]string{{command, "--help"}, {command, "-h"}, {"help", command}} {
				name := executable + " " + strings.Join(form, " ")
				t.Run(name, func(t *testing.T) {
					// No SSM_MASTER_PASS_FILE and --json must not matter: help never unlocks.
					result := cli.run(t, executable, nil, env, form...)
					if result.ProcessExit != 0 {
						t.Fatalf("help exit = %d: %s", result.ProcessExit, compiledOutputIdentity(result))
					}
					output := result.Stdout + result.Stderr
					if !strings.Contains(output, "Usage") {
						t.Fatalf("help printed no usage: %s", compiledOutputIdentity(result))
					}
					for _, canary := range []string{"HELP_SIDE_EFFECT_TOKEN_CANARY", "ISSUE17_MASTER_PASSPHRASE_CANARY", "Vault pulled", "master_pass_file"} {
						if strings.Contains(output, canary) {
							t.Fatalf("help output contains %q: %s", canary, compiledOutputIdentity(result))
						}
					}
					if got := requests.Load(); got != 0 {
						t.Fatalf("help made %d HTTP request(s) to the sync server", got)
					}
					if got := len(compiledUpdateServer.RequestPaths()); got != updateRequests {
						t.Fatalf("help made %d update-server request(s)", got-updateRequests)
					}
					if after := snapshotTree(t, configDir); !reflect.DeepEqual(before, after) {
						t.Fatalf("help changed the config directory:\nbefore=%v\nafter=%v", before, after)
					}
				})
			}
		}
	}
}

func TestCompiledSSMPushHelpPrintsUsage(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	result := cli.RunWithoutMasterPass(t, "ssm", nil, "push", "--help")
	if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "push (--only <transaction-id> | --all)") || result.Stderr != "" {
		t.Fatalf("ssm push --help: %s", compiledOutputIdentity(result))
	}
}

func TestCompiledDefaultMasterPassFileForBothEntrypoints(t *testing.T) {
	for _, executable := range []string{"ssm", "sshctl"} {
		t.Run(executable+" unlocks with <config dir>/master.pass", func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: "alpha", Host: "192.0.2.1", Port: 22, User: "u", Password: "p"}}})
			result := cli.RunWithoutMasterPass(t, executable, nil, "--offline", "list", "--json")
			items, ok := decodeExactlyOneJSONValue(t, result.Stdout).([]any)
			if result.ProcessExit != 0 || !ok || len(items) != 1 {
				t.Fatalf("default master.pass did not unlock: %s", compiledOutputIdentity(result))
			}
		})
	}
	t.Run("ssm without master.pass keeps master_pass_file_required", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{})
		if err := os.Remove(cli.passPath); err != nil {
			t.Fatal(err)
		}
		result := cli.RunWithoutMasterPass(t, "ssm", nil, "--offline", "--json", "list")
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "master_pass_file_required", JSONExit: 2, ProcessExit: 2,
			Hint: "provide --master-pass-file or SSM_MASTER_PASS_FILE; credentials are never accepted inline",
		})
	})
}

// Without any master pass (no env, no default file) help must still work: it
// never unlocks the vault.
func TestCompiledSubcommandHelpWorksWithoutMasterPass(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	cli.SaveVault(t, &config.Vault{})
	if err := os.Remove(cli.passPath); err != nil {
		t.Fatal(err)
	}
	for _, executable := range []string{"sshctl", "ssm"} {
		for _, command := range helpSubcommands[executable] {
			t.Run(executable+" "+command+" --help", func(t *testing.T) {
				result := cli.RunWithoutMasterPass(t, executable, nil, command, "--help")
				output := result.Stdout + result.Stderr
				if result.ProcessExit != 0 || !strings.Contains(output, "Usage") || strings.Contains(output, "master_pass_file") {
					t.Fatalf("help without master pass: %s", compiledOutputIdentity(result))
				}
			})
		}
	}
}

func TestCompiledSSMHelpForSSHCTLOnlyCommandsPointsAtSSHCTL(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	for _, command := range []string{"request", "sync", "host-key", "status", "shell", "known-hosts"} {
		t.Run(command, func(t *testing.T) {
			result := cli.RunWithoutMasterPass(t, "ssm", nil, command, "--help")
			if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "ssm has no "+command+" command") || !strings.Contains(result.Stdout, "sshctl") {
				t.Fatalf("ssm %s --help: %s", command, compiledOutputIdentity(result))
			}
		})
	}
}

func TestCompiledSSMUnknownCommandKeepsJSONError(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	result := cli.RunWithoutMasterPass(t, "ssm", nil, "foo", "x", "--json")
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	if result.ProcessExit == 0 || value["ok"] != false {
		t.Fatalf("ssm unknown command JSON error changed: %s", compiledOutputIdentity(result))
	}
}
