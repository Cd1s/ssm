package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
)

const hostKeyTypesPassword = "ISSUE74_HOST_KEY_TYPES_PASSWORD_CANARY"

func randomCompiledPublicKey(t *testing.T, kind string) gossh.PublicKey {
	t.Helper()
	var public any
	switch kind {
	case "ed25519":
		key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public = key
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public = &key.PublicKey
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	key, err := gossh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeCompiledKnownHosts(t *testing.T, cli *compiledCLIHarness, content string) string {
	t.Helper()
	directory := filepath.Join(cli.home, ".ssh")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "known_hosts")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func compiledKnownLine(host string, key gossh.PublicKey) string {
	return knownhosts.Line([]string{host}, key) + "\n"
}

func saveHostKeyTypesVault(t *testing.T, cli *compiledCLIHarness, server *compiledSSHFixture) {
	t.Helper()
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("hk", hostKeyTypesPassword)}})
}

func TestCompiledRunSucceedsWhenKnownHostsHoldsOnlyEd25519AndServerOffersECDSAToo(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: hostKeyTypesPassword, HostKeyTypes: []string{"ecdsa", "ed25519"},
	})
	saveHostKeyTypesVault(t, cli, server)
	writeCompiledKnownHosts(t, cli, compiledKnownLine(knownhosts.Normalize(server.Address()), server.signers["ed25519"].PublicKey()))

	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "hk", "--argv", "true")
	assertNoCompiledCanaryLeak(t, result, map[string]string{"password": hostKeyTypesPassword})
	assertCompiledJSONSuccess(t, result)

	inspection := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "hk")
	value := assertCompiledJSONSuccess(t, inspection)
	assertCompiledStringField(t, value, "status", "trusted", inspection)
	assertCompiledStringField(t, value, "algorithm", "ssh-ed25519", inspection)
}

func TestCompiledHostKeyTypeChangeIsDistinctFromSameTypeMismatch(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: hostKeyTypesPassword})
	saveHostKeyTypesVault(t, cli, server)
	token := knownhosts.Normalize(server.Address())

	t.Run("only other key types known", func(t *testing.T) {
		writeCompiledKnownHosts(t, cli, compiledKnownLine(token, randomCompiledPublicKey(t, "ecdsa")))
		run := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "hk", "--argv", "true")
		assertCompiledMachineContract(t, run, compiledMachineContract{
			OK: false, Error: "host_key_type_changed", Stage: "dial", JSONExit: 255, ProcessExit: 255,
			Cardinality: "one_value",
		})
		if !strings.Contains(decodeExactlyOneJSONObject(t, run.Stdout)["hint"].(string), "host-key inspect") {
			t.Fatalf("type change hint does not point at host-key inspect: %s", compiledOutputIdentity(run))
		}
		inspection := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "hk")
		value := assertCompiledJSONSuccess(t, inspection)
		assertCompiledStringField(t, value, "status", "type_changed", inspection)
		assertCompiledStringField(t, value, "classification", "type_changed", inspection)
	})

	t.Run("same key type changed", func(t *testing.T) {
		writeCompiledKnownHosts(t, cli, compiledKnownLine(token, randomCompiledPublicKey(t, "ed25519")))
		run := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "hk", "--argv", "true")
		assertCompiledMachineContract(t, run, compiledMachineContract{
			OK: false, Error: "host_key_mismatch", Stage: "dial", JSONExit: 255, ProcessExit: 255,
			Cardinality: "one_value",
		})
		inspection := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "hk")
		value := assertCompiledJSONSuccess(t, inspection)
		assertCompiledStringField(t, value, "status", "mismatch", inspection)
	})
}

func TestCompiledAcceptKeepsOtherKeyTypesAndOtherHostsByteForByte(t *testing.T) {
	cases := []struct {
		name     string
		known    func(token string) []string // lines kept verbatim
		replaced func(token string) []string // lines expected to disappear
		status   string
	}{
		{
			name:   "type change adds the new type",
			status: "type_changed",
			known: func(token string) []string {
				return []string{"# hand written\n", compiledKnownLine("other.example", randomCompiledPublicKey(t, "ed25519")), compiledKnownLine(token, randomCompiledPublicKey(t, "ecdsa"))}
			},
			replaced: func(string) []string { return nil },
		},
		{
			name:   "same type change replaces only that type",
			status: "mismatch",
			known: func(token string) []string {
				return []string{"# hand written\n", compiledKnownLine("other.example", randomCompiledPublicKey(t, "ed25519")), compiledKnownLine(token, randomCompiledPublicKey(t, "ecdsa"))}
			},
			replaced: func(token string) []string {
				return []string{compiledKnownLine(token, randomCompiledPublicKey(t, "ed25519"))}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: hostKeyTypesPassword})
			saveHostKeyTypesVault(t, cli, server)
			token := knownhosts.Normalize(server.Address())
			kept := tc.known(token)
			path := writeCompiledKnownHosts(t, cli, strings.Join(kept, "")+strings.Join(tc.replaced(token), ""))

			inspection := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "hk")
			value := assertCompiledJSONSuccess(t, inspection)
			assertCompiledStringField(t, value, "status", tc.status, inspection)
			fingerprint := value["observed_fingerprint"].(string)

			accepted := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "accept", "hk", "--fingerprint", fingerprint, "--yes")
			assertCompiledJSONSuccess(t, accepted)

			got, err := os.ReadFile(path) //nolint:gosec // harness-owned isolated known_hosts
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Join(kept, "") + compiledKnownLine(token, server.signers["ed25519"].PublicKey())
			if string(got) != want {
				t.Fatalf("known_hosts after accept:\n%s\nwant:\n%s", got, want)
			}
			assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "hk", "--argv", "true"))
		})
	}
}

func TestCompiledHostKeyInspectFailureKeepsObservedFieldsAtTopLevel(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: hostKeyTypesPassword})
	saveHostKeyTypesVault(t, cli, server)

	success := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "hk")
	successValue := assertCompiledJSONSuccess(t, success)
	fingerprint, _ := successValue["observed_fingerprint"].(string)
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("success document lacks top-level observed_fingerprint: %s", compiledOutputIdentity(success))
	}

	// A malformed known_hosts fails inspection after the key was observed.
	writeCompiledKnownHosts(t, cli, "this is not a known_hosts line\n")
	failure := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "hk")
	if failure.ProcessExit == 0 {
		t.Fatalf("malformed known_hosts inspection succeeded: %s", compiledOutputIdentity(failure))
	}
	value := decodeExactlyOneJSONObject(t, failure.Stdout)
	if ok, _ := value["ok"].(bool); ok {
		t.Fatalf("failure document has ok=true: %s", compiledOutputIdentity(failure))
	}
	for _, field := range []string{"observed_fingerprint", "fingerprint"} {
		assertCompiledStringField(t, value, field, fingerprint, failure)
	}
	for _, field := range []string{"algorithm", "address", "host", "known_hosts_path"} {
		if text, _ := value[field].(string); text == "" {
			t.Fatalf("failure document lacks top-level %s: %s", field, compiledOutputIdentity(failure))
		}
	}
	nested, ok := value["inspection"].(map[string]any)
	if !ok || nested["observed_fingerprint"] != fingerprint {
		t.Fatalf("nested inspection field was removed or changed: %s", compiledOutputIdentity(failure))
	}
	for _, field := range []string{"error", "stage", "exit", "hint"} {
		if _, ok := value[field]; !ok {
			t.Fatalf("failure metadata field %q missing: %s", field, compiledOutputIdentity(failure))
		}
	}
}
