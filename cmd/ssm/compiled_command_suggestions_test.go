package main

import (
	"strings"
	"testing"

	"ssm/internal/config"
)

func newSuggestionCLI(t *testing.T) (*compiledCLIHarness, *compiledSSHFixture) {
	t.Helper()
	const password = "COMMAND_SUGGESTION_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("web-prod1", password)}})
	return cli, server
}

func requireNoSSHSession(t *testing.T, server *compiledSSHFixture) {
	t.Helper()
	if server.SessionCount() != 0 || server.ConnectionCount() != 0 {
		t.Fatalf("suggestion must never connect: sessions=%d connections=%d", server.SessionCount(), server.ConnectionCount())
	}
}

func TestCompiledSSHCTLUnknownCommandSuggestsSSM(t *testing.T) {
	cli, server := newSuggestionCLI(t)
	t.Run("human", func(t *testing.T) {
		result := cli.Run(t, "sshctl", nil, "--offline", "keys", "list")
		if result.ProcessExit != 2 || !strings.Contains(result.Stderr, "error=unknown_command") ||
			!strings.Contains(result.Stderr, "`keys` is an ssm command; run `ssm keys ...`") {
			t.Fatalf("keys: %s", compiledOutputIdentity(result))
		}
	})
	t.Run("json", func(t *testing.T) {
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "keys", "list")
		document := decodeExactlyOneJSONObject(t, result.Stdout)
		if result.ProcessExit != 2 || document["error"] != "unknown_command" || document["exit"] != float64(2) ||
			!strings.Contains(document["hint"].(string), "`keys` is an ssm command; run `ssm keys ...`") {
			t.Fatalf("keys json: %s", compiledOutputIdentity(result))
		}
	})
	t.Run("vault has no entrypoint", func(t *testing.T) {
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "vault", "list")
		document := decodeExactlyOneJSONObject(t, result.Stdout)
		hint, _ := document["hint"].(string)
		if result.ProcessExit != 2 || document["error"] != "unknown_command" ||
			!strings.Contains(hint, "ssm") || !strings.Contains(hint, "host list") {
			t.Fatalf("vault: %s", compiledOutputIdentity(result))
		}
		human := cli.Run(t, "sshctl", nil, "--offline", "vault", "list")
		if human.ProcessExit != 2 || !strings.Contains(human.Stderr, "host list") || !strings.Contains(human.Stderr, "ssm") {
			t.Fatalf("vault human: %s", compiledOutputIdentity(human))
		}
	})
	t.Run("single word", func(t *testing.T) {
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "login")
		document := decodeExactlyOneJSONObject(t, result.Stdout)
		if result.ProcessExit != 2 || document["error"] != "unknown_command" ||
			!strings.Contains(document["hint"].(string), "run `ssm login ...`") {
			t.Fatalf("login: %s", compiledOutputIdentity(result))
		}
	})
	requireNoSSHSession(t, server)
}

func TestCompiledSSHCTLUnknownCommandSuggestsNearestSubcommand(t *testing.T) {
	cli, server := newSuggestionCLI(t)
	for _, tc := range []struct{ typo, want string }{{"stauts", "status"}, {"hostkey", "host-key"}} {
		t.Run(tc.typo+" json", func(t *testing.T) {
			result := cli.Run(t, "sshctl", nil, "--offline", "--json", tc.typo)
			document := decodeExactlyOneJSONObject(t, result.Stdout)
			hint, _ := document["hint"].(string)
			if result.ProcessExit != 2 || document["error"] != "unknown_command" || !strings.Contains(hint, "`sshctl "+tc.want+"`") {
				t.Fatalf("%s: %s", tc.typo, compiledOutputIdentity(result))
			}
		})
		t.Run(tc.typo+" human with arguments", func(t *testing.T) {
			result := cli.Run(t, "sshctl", nil, "--offline", tc.typo, "extra")
			if result.ProcessExit != 2 || !strings.Contains(result.Stderr, "error=unknown_command") ||
				!strings.Contains(result.Stderr, "`sshctl "+tc.want+"`") {
				t.Fatalf("%s: %s", tc.typo, compiledOutputIdentity(result))
			}
		})
	}
	requireNoSSHSession(t, server)
}

func TestCompiledSSHCTLAliasTypoOffersCandidatesWithoutConnecting(t *testing.T) {
	cli, server := newSuggestionCLI(t)
	t.Run("json", func(t *testing.T) {
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "web-prd1", "--argv", "hostname")
		document := decodeExactlyOneJSONObject(t, result.Stdout)
		if result.ProcessExit == 0 || document["error"] != "alias_not_found" || !strings.Contains(result.Stdout, "web-prod1") {
			t.Fatalf("run typo: %s", compiledOutputIdentity(result))
		}
	})
	t.Run("shorthand human", func(t *testing.T) {
		result := cli.Run(t, "sshctl", nil, "--offline", "web-prd1", "hostname")
		if result.ProcessExit != 255 || !strings.Contains(result.Stderr, "error=alias_not_found") ||
			!strings.Contains(result.Stderr, "Did you mean: web-prod1") {
			t.Fatalf("shorthand typo: %s", compiledOutputIdentity(result))
		}
	})
	t.Run("shorthand json", func(t *testing.T) {
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "web-prd1", "hostname")
		document := decodeExactlyOneJSONObject(t, result.Stdout)
		candidates, _ := document["candidates"].([]any)
		if result.ProcessExit != 255 || document["error"] != "alias_not_found" || len(candidates) != 1 || candidates[0] != "web-prod1" {
			t.Fatalf("shorthand typo json: %s", compiledOutputIdentity(result))
		}
	})
	requireNoSSHSession(t, server)
}

func TestCompiledSSHCTLShorthandStillRunsExistingAlias(t *testing.T) {
	const password = "COMMAND_SUGGESTION_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password:           password,
		RunCommandContains: "hostname",
		RunStdoutFragments: []string{"ran\n"},
	})
	cli.TrustSSHHost(t, server)
	// The alias deliberately collides with an ssm-only command name.
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("keys", password)}})
	result := cli.Run(t, "sshctl", nil, "--offline", "keys", "hostname")
	if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "ran\n") {
		t.Fatalf("existing alias must win: %s", compiledOutputIdentity(result))
	}
}

func TestCompiledSSMUnknownCommandSuggestions(t *testing.T) {
	cli, server := newSuggestionCLI(t)
	t.Run("sshctl only command json", func(t *testing.T) {
		result := cli.Run(t, "ssm", nil, "--offline", "--json", "status")
		document := decodeExactlyOneJSONObject(t, result.Stdout)
		if result.ProcessExit != 2 || document["error"] != "unknown_command" ||
			!strings.Contains(document["hint"].(string), "`status` is an sshctl command; run `sshctl status ...`") {
			t.Fatalf("ssm status: %s", compiledOutputIdentity(result))
		}
	})
	t.Run("sshctl only command human", func(t *testing.T) {
		result := cli.Run(t, "ssm", nil, "--offline", "host-key", "inspect", "x")
		if result.ProcessExit != 2 || !strings.Contains(result.Stderr, "error=unknown_command") ||
			!strings.Contains(result.Stderr, "run `sshctl host-key ...`") {
			t.Fatalf("ssm host-key: %s", compiledOutputIdentity(result))
		}
	})
	t.Run("typo", func(t *testing.T) {
		result := cli.Run(t, "ssm", nil, "--offline", "--json", "pul")
		document := decodeExactlyOneJSONObject(t, result.Stdout)
		if result.ProcessExit != 2 || document["error"] != "unknown_command" ||
			!strings.Contains(document["hint"].(string), "`ssm pull`") {
			t.Fatalf("ssm pul: %s", compiledOutputIdentity(result))
		}
		human := cli.Run(t, "ssm", nil, "--offline", "impotr-json", "x")
		if human.ProcessExit != 2 || !strings.Contains(human.Stderr, "`ssm import-json`") {
			t.Fatalf("ssm impotr-json: %s", compiledOutputIdentity(human))
		}
	})
	requireNoSSHSession(t, server)
}

func TestCompiledRunUnknownOptionSuggestions(t *testing.T) {
	cli, server := newSuggestionCLI(t)
	for _, tc := range []struct{ name, option, want string }{
		{"script-file", "--script-file", "-f"},
		{"fetch", "--fetch", "sshctl get"},
		{"near miss", "--timout", "--timeout"},
	} {
		t.Run(tc.name+" human", func(t *testing.T) {
			result := cli.Run(t, "sshctl", nil, "--offline", "run", "web-prod1", tc.option, "x.sh")
			if result.ProcessExit != 2 || !strings.Contains(result.Stderr, "error=invalid_arguments") ||
				!strings.Contains(result.Stderr, "unknown run option: "+tc.option) || !strings.Contains(result.Stderr, tc.want) {
				t.Fatalf("%s: %s", tc.option, compiledOutputIdentity(result))
			}
		})
		t.Run(tc.name+" json", func(t *testing.T) {
			result := cli.Run(t, "sshctl", nil, "--offline", "run", "web-prod1", "--json", tc.option, "x.sh")
			document := decodeExactlyOneJSONObject(t, result.Stdout)
			hint, _ := document["hint"].(string)
			if result.ProcessExit != 2 || document["error"] != "invalid_arguments" || !strings.Contains(hint, tc.want) {
				t.Fatalf("%s json: %s", tc.option, compiledOutputIdentity(result))
			}
		})
	}
	requireNoSSHSession(t, server)
}
