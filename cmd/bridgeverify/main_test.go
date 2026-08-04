package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCandidateChecksumManifestMaterializesExactInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checksums.txt")
	names := []string{"ssm-linux-amd64", "install.sh"}
	checksums := map[string]string{
		"ssm-linux-amd64": strings.Repeat("a", 64),
		"install.sh":      strings.Repeat("b", 64),
	}
	entries, manifestDigest, err := materializeAndVerifyChecksums(path, names, checksums)
	if err != nil {
		t.Fatal(err)
	}
	if entries != len(names) || len(manifestDigest) != 64 {
		t.Fatalf("checksum proof entries=%d digest=%q", entries, manifestDigest)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test-owned checksum manifest
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("a", 64) + "  ssm-linux-amd64\n" + strings.Repeat("b", 64) + "  install.sh\n"
	if string(data) != want {
		t.Fatalf("checksum manifest = %q, want %q", data, want)
	}
}

func TestSourceVersionAndCandidateNotesAgree(t *testing.T) {
	repo := filepath.Join("..", "..")
	version, err := readSourceVersion(repo)
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.4.4" {
		t.Fatalf("bridge source version = %q, want 1.4.4", version)
	}
	notes, err := readReleaseNotes(repo, "v"+version)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) == 0 {
		t.Fatal("bridge candidate release notes are empty")
	}
}

func TestV1PreservationAllowlistRejectsRuntimeBackports(t *testing.T) {
	for _, path := range []string{
		"cmd/ssm/stream.go",
		"internal/synctransaction/transaction.go",
		"internal/machinecontract/contract.go",
		"internal/config/config.go",
	} {
		if pathAllowedForBridge(path) {
			t.Fatalf("unrelated v1/v2 runtime path allowed: %q", path)
		}
	}
	for _, path := range []string{
		"cmd/ssm/main.go",
		"internal/update/update.go",
		"internal/provenance/provenance.go",
		"internal/releaseasset/targets.go",
		"docs/plans/issue-47-v1-major-safety-bridge.md",
	} {
		if !pathAllowedForBridge(path) {
			t.Fatalf("bridge seam rejected: %q", path)
		}
	}
}

func TestCandidateVerifierDoesNotNeedPublicationCredentials(t *testing.T) {
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN", "SIGSTORE_ID_TOKEN"} {
		t.Setenv(name, "")
	}
	directory := t.TempDir()
	before, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 0 {
		t.Fatal("test temporary directory is not empty")
	}
	if err := verifySyntheticProvenance("ssm-linux-amd64", "v1.4.4", []byte("test-owned asset")); err != nil {
		t.Fatalf("credential-free synthetic provenance: %v", err)
	}
}
