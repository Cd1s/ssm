//go:build unix

package main

import (
	"context"
	"io"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReleaseRunsInstallerSyntaxAsAnAction(t *testing.T) {
	release, ok := findProfile(verificationManifest(), "release")
	if !ok {
		t.Fatal("release profile not found")
	}
	var syntax Check
	for _, check := range release.Checks {
		if check.ID == "install-shell-syntax" {
			syntax = check
			break
		}
	}
	wantAction := commandAction("sh", []string{"-n", "install.sh"}, nil, "")
	if !reflect.DeepEqual(syntax.Action, wantAction) {
		t.Fatalf("installer syntax action = %+v, want %+v", syntax.Action, wantAction)
	}
	if syntax.Requirement != requirementRequired {
		t.Fatalf("installer syntax requirement = %q, want required", syntax.Requirement)
	}

	repo := t.TempDir()
	writeTestFile(t, filepath.Join(repo, "install.sh"), "#!/bin/sh\nif then\n")
	result := executeAction(context.Background(), syntax.Action, actionContext{
		RepoRoot:    repo,
		Environment: newTestProcessEnvironment(t),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if result.Status != statusFailed {
		t.Fatalf("malformed installer syntax status = %q, want failed", result.Status)
	}
}
