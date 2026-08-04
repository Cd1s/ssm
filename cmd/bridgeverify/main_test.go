package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
