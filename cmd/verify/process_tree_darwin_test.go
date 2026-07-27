//go:build darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestOwnedCommandFailsClosedBeforeDarwinTargetLaunch(t *testing.T) {
	if marker := os.Getenv("SSM_VERIFY_DARWIN_FAIL_CLOSED_MARKER"); marker != "" {
		if err := os.WriteFile(marker, []byte("started"), 0o600); err != nil { //nolint:gosec // path is supplied by the parent test from its private t.TempDir
			t.Fatal(err)
		}
		return
	}
	marker := t.TempDir() + "/target-started"
	command := exec.Command(os.Args[0], "-test.run=^TestOwnedCommandFailsClosedBeforeDarwinTargetLaunch$")
	command.Env = append(os.Environ(), "SSM_VERIFY_DARWIN_FAIL_CLOSED_MARKER="+marker)
	err := runOwnedCommand(context.Background(), command)
	if err == nil || !strings.Contains(err.Error(), "cannot guarantee stable command-tree ownership on Darwin") {
		t.Fatalf("owned command error = %v, want Darwin stable-ownership failure", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Darwin target was launched before ownership failed closed: %v", err)
	}
}
