package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"ssm/internal/config"
)

type compiledTransferFixture struct {
	cli        *compiledCLIHarness
	alias      string
	localFile  string
	localDir   string
	remoteFile string
	remoteDir  string
}

func newCompiledTransferFixture(t *testing.T) compiledTransferFixture {
	t.Helper()
	cli := newCompiledCLIHarness(t)
	const alias = "outcome"
	const password = "ISSUE26_TRANSFER_PASSWORD_CANARY"
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection(alias, password)}})

	localFile := filepath.Join(cli.temp, "source.bin")
	if err := os.WriteFile(localFile, []byte("truthful transfer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	localDir := filepath.Join(cli.temp, "source-dir")
	if err := os.Mkdir(localDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "item"), []byte("directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteRoot := t.TempDir()
	return compiledTransferFixture{
		cli: cli, alias: alias, localFile: localFile, localDir: localDir,
		remoteFile: filepath.Join(remoteRoot, "file"), remoteDir: filepath.Join(remoteRoot, "dir"),
	}
}

func transferJSON(t *testing.T, result compiledCLIResult) map[string]any {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" {
		t.Fatalf("transfer failed: %s", compiledOutputIdentity(result))
	}
	return decodeExactlyOneJSONObject(t, result.Stdout)
}

func requestTransfer(t *testing.T, f compiledTransferFixture, op, remote, local string) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"version": 1, "op": op, "alias": f.alias, "remote_path": remote, "local_path": local,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transferJSON(t, f.cli.Run(t, "sshctl", body, "request", "-"))
}

func assertTransferIdentity(t *testing.T, got map[string]any, direction, kind string) {
	t.Helper()
	if got["direction"] != direction || got["kind"] != kind {
		t.Fatalf("transfer identity direction=%v kind=%v, want %s/%s; fields=%v", got["direction"], got["kind"], direction, kind, got)
	}
}

func TestCompiledTransferOutcomeMatrix(t *testing.T) {
	f := newCompiledTransferFixture(t)
	filePut := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", f.alias, f.localFile, f.remoteFile))
	assertTransferIdentity(t, filePut, "put", "file")
	dirPut := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", f.alias, f.localDir, f.remoteDir))
	assertTransferIdentity(t, dirPut, "put", "directory")

	fileGet := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", f.alias, f.remoteFile, filepath.Join(f.cli.temp, "direct-file")))
	assertTransferIdentity(t, fileGet, "get", "file")
	dirGet := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", f.alias, f.remoteDir, filepath.Join(f.cli.temp, "direct-dir")))
	assertTransferIdentity(t, dirGet, "get", "directory")
}

func TestRequestV1GetRejectsExplicitFalseUnsupportedFields(t *testing.T) {
	f := newCompiledTransferFixture(t)
	for _, field := range []string{"deep", "no_reuse", "sha256"} {
		t.Run(field, func(t *testing.T) {
			request := map[string]any{
				"version": 1, "op": "get", "alias": f.alias,
				"remote_path": f.remoteFile, "local_path": filepath.Join(f.cli.temp, "rejected-"+field),
				field: false,
			}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			result := f.cli.Run(t, "sshctl", body, "request", "-")
			if result.ProcessExit == 0 || result.Stderr != "" {
				t.Fatalf("explicit false %s was not rejected: %s", field, compiledOutputIdentity(result))
			}
			failure := decodeExactlyOneJSONObject(t, result.Stdout)
			if failure["error"] != "invalid_request" {
				t.Fatalf("explicit false %s error=%v, want invalid_request; output=%s", field, failure["error"], compiledOutputIdentity(result))
			}
		})
	}
}

func TestTransferDirectAndRequestParity(t *testing.T) {
	f := newCompiledTransferFixture(t)
	assertParity := func(name string, direct, request map[string]any, fields ...string) {
		t.Helper()
		for _, field := range fields {
			if !reflect.DeepEqual(direct[field], request[field]) {
				t.Errorf("%s %s direct=%v request=%v", name, field, direct[field], request[field])
			}
		}
	}
	common := []string{"ok", "action", "direction", "kind", "stage", "integrity", "atomic", "resume"}

	directFilePut := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", f.alias, f.localFile, f.remoteFile))
	requestFilePut := requestTransfer(t, f, "put", filepath.Join(filepath.Dir(f.remoteFile), "request-file"), f.localFile)
	assertParity("file put", directFilePut, requestFilePut, append(common, "bytes_sent")...)

	directDirPut := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", f.alias, f.localDir, f.remoteDir))
	requestDirPut := requestTransfer(t, f, "put", filepath.Join(filepath.Dir(f.remoteDir), "request-dir"), f.localDir)
	assertParity("directory put", directDirPut, requestDirPut, append(common, "bytes_sent")...)

	directFileGet := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", f.alias, f.remoteFile, filepath.Join(f.cli.temp, "direct-file")))
	requestFileGet := requestTransfer(t, f, "get", f.remoteFile, filepath.Join(f.cli.temp, "request-file-get"))
	assertParity("file get", directFileGet, requestFileGet, append(common, "bytes_received")...)

	directDirGet := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", f.alias, f.remoteDir, filepath.Join(f.cli.temp, "direct-dir")))
	requestDirGet := requestTransfer(t, f, "get", f.remoteDir, filepath.Join(f.cli.temp, "request-dir-get"))
	assertParity("directory get", directDirGet, requestDirGet, common...)
	if _, directPresent := directDirGet["bytes_received"]; directPresent {
		t.Error("direct directory get must omit bytes_received")
	}
	if _, requestPresent := requestDirGet["bytes_received"]; requestPresent {
		t.Error("request directory get must omit bytes_received")
	}
}

func TestTransferGuaranteesAreTruthful(t *testing.T) {
	f := newCompiledTransferFixture(t)
	dirPut := transferJSON(t, f.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", f.alias, f.localDir, f.remoteDir))
	for field, want := range map[string]any{"atomic": false, "integrity": "not_available", "resume": "unsupported"} {
		if dirPut[field] != want {
			t.Errorf("directory put %s=%v, want %v", field, dirPut[field], want)
		}
	}
	dirGet := requestTransfer(t, f, "get", f.remoteDir, filepath.Join(f.cli.temp, "request-dir"))
	for field, want := range map[string]any{"atomic": false, "integrity": "not_available", "resume": "unsupported"} {
		if dirGet[field] != want {
			t.Errorf("directory get %s=%v, want %v", field, dirGet[field], want)
		}
	}
	if _, present := dirGet["bytes_received"]; present {
		t.Error("directory get must omit bytes_received")
	}

	existing := filepath.Join(f.cli.temp, "preserved")
	if err := os.WriteFile(existing, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", f.alias, filepath.Join(t.TempDir(), "missing"), existing)
	if failed.ProcessExit == 0 || failed.Stderr != "" {
		t.Fatalf("missing get outcome: %s", compiledOutputIdentity(failed))
	}
	failure := decodeExactlyOneJSONObject(t, failed.Stdout)
	if failure["direction"] != "get" || failure["kind"] != "unknown" || failure["stage"] != "discovery" {
		t.Fatalf("discovery failure identity=%v", failure)
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "keep\n" { //nolint:gosec // existing is a harness-owned path beneath t.TempDir
		t.Fatalf("failed get changed existing destination: data=%q err=%v", data, err)
	}
	if temps, err := filepath.Glob(filepath.Join(f.cli.temp, ".ssm-get-*")); err != nil || len(temps) != 0 {
		t.Fatalf("failed get temporary outputs=%v err=%v", temps, err)
	}
}
