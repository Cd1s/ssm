package main

import (
	"strings"
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

func TestParseDirModeRequiresOwnerWriteAndExecute(t *testing.T) {
	for _, bad := range []string{"0500", "0644", "0", "0999", "1777", "abc"} {
		if _, err := parseDirMode(bad); err == nil {
			t.Errorf("parseDirMode(%q) accepted an unusable mode", bad)
		}
	}
	if err := func() error { _, err := parseDirMode("0500"); return err }(); err == nil || !strings.Contains(err.Error(), "0300") {
		t.Errorf("error should explain the owner write/execute requirement: %v", err)
	}
	for _, good := range []string{"0755", "755", "0700", "0750", "0300"} {
		if _, err := parseDirMode(good); err != nil {
			t.Errorf("parseDirMode(%q): %v", good, err)
		}
	}
}

func TestParsePutAndGetAcceptSFTPFlag(t *testing.T) {
	previousJSON := machineJSON
	t.Cleanup(func() { machineJSON = previousJSON })
	put, err := parsePutArgs([]string{"prod", "local.bin", "/srv/remote.bin", "--sftp", "--sha256"})
	if err != nil {
		t.Fatal(err)
	}
	if !put.sftp || !put.verifySHA256 {
		t.Fatalf("put options = %+v", put)
	}
	get, err := parseGetArgs([]string{"--sftp", "prod", "/srv/remote.bin", "local.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if !get.sftp || get.name != "prod" {
		t.Fatalf("get options = %+v", get)
	}
	plain, err := parsePutArgs([]string{"prod", "local.bin", "/srv/remote.bin"})
	if err != nil || plain.sftp {
		t.Fatalf("--sftp must be opt-in: %+v %v", plain, err)
	}
}
