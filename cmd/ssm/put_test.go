package main

import (
	"testing"
	"time"
)

func TestParsePutReliabilityOptions(t *testing.T) {
	previousJSON := machineJSON
	machineJSON = false
	t.Cleanup(func() { machineJSON = previousJSON })
	opts, err := parsePutArgs([]string{"prod", "local.bin", "/srv/remote.bin", "--resume=v1", "--sha256", "--timeout=30s", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.name != "prod" || opts.localPath != "local.bin" || opts.remotePath != "/srv/remote.bin" || opts.resumeVersion != "v1" || !opts.verifySHA256 || opts.timeout != 30*time.Second || !machineJSON {
		t.Fatalf("options = %+v json=%t", opts, machineJSON)
	}
}

func TestParsePutRejectsInvalidTimeoutAndUnknownOptions(t *testing.T) {
	for _, args := range [][]string{
		{"prod", "local", "remote", "--timeout", "0s"},
		{"prod", "local", "remote", "--resume=v2"},
		{"prod", "local"},
	} {
		if _, err := parsePutArgs(args); err == nil {
			t.Fatalf("accepted invalid put args: %v", args)
		}
	}
}
