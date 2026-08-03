package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestSSHCTLCommandHelpNeedsNoUnlockOrTTY(t *testing.T) {
	commands := []string{"request", "push", "put", "get", "run", "map", "host", "host-key", "doctor", "status", "sync", "pull", "redirect"}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			masterPassFile = "/does/not/exist"
			out := captureHelpOutput(t, func() { runSSHCTL([]string{command, "--help"}) })
			if !strings.Contains(out, "Usage:") || strings.Contains(strings.ToLower(out), "password=") {
				t.Fatalf("help output = %q", out)
			}
		})
	}
}

func TestSSHCTLHelpFormsAndSubcommand(t *testing.T) {
	for _, args := range [][]string{{"help", "push"}, {"push", "help"}, {"host", "add", "--help"}} {
		out := captureHelpOutput(t, func() { runSSHCTL(args) })
		if !strings.Contains(out, "Usage:") {
			t.Fatalf("help %v = %q", args, out)
		}
	}
}

func TestRunHelpDocumentsFastStream(t *testing.T) {
	for _, command := range []string{"run", "exec", "plan"} {
		t.Run(command, func(t *testing.T) {
			out := captureHelpOutput(t, func() { runSSHCTL([]string{command, "--help"}) })
			if !strings.Contains(out, "--stream") || !strings.Contains(out, "JSON string array") || !strings.Contains(out, "compact NDJSON") {
				t.Fatalf("%s help does not document stream mode: %q", command, out)
			}
			if count := strings.Count(out, "Usage: sshctl "+command+" "); count != 1 {
				t.Fatalf("%s help has %d Usage blocks, want exactly 1: %q", command, count, out)
			}
		})
	}
}

func captureHelpOutput(t *testing.T, fn func()) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	defer func() { os.Stdout = original }()
	fn()
	_ = write.Close()
	data, err := io.ReadAll(read)
	_ = read.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
