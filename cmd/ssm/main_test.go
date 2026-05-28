package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseGlobalArgsExtractsMasterPassFile(t *testing.T) {
	old := masterPassFile
	t.Cleanup(func() { masterPassFile = old })
	masterPassFile = ""

	got, err := parseGlobalArgs([]string{"--master-pass-file", "/tmp/pass", "list", "--json"})
	if err != nil {
		t.Fatalf("parseGlobalArgs: %v", err)
	}
	if masterPassFile != "/tmp/pass" {
		t.Fatalf("masterPassFile = %q", masterPassFile)
	}
	if !reflect.DeepEqual(got, []string{"list", "--json"}) {
		t.Fatalf("args = %#v", got)
	}
}

func TestParseGlobalArgsRejectsEmptyMasterPassFile(t *testing.T) {
	old := masterPassFile
	t.Cleanup(func() { masterPassFile = old })
	masterPassFile = ""

	for _, args := range [][]string{
		{"--master-pass-file"},
		{"--master-pass-file="},
	} {
		if _, err := parseGlobalArgs(args); err == nil {
			t.Fatalf("parseGlobalArgs(%v) accepted missing path", args)
		}
	}
}

func TestRedactStringRemovesSensitiveFields(t *testing.T) {
	in := "password=hunter2 token:abc123 authorization: bearer deadbeef private_key=inline"
	got := redactString(in)
	for _, secret := range []string{"hunter2", "abc123", "deadbeef", "inline"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted string %q still contains %q", got, secret)
		}
	}
}

func TestRedactStringRemovesPrivateKeyBlocks(t *testing.T) {
	in := "bad key -----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key\n-----END OPENSSH PRIVATE KEY-----"
	got := redactString(in)
	if strings.Contains(got, "secret-key") || strings.Contains(got, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("private key block was not redacted: %q", got)
	}
}

func TestRedactStringKeepsPlainWrongPasswordDiagnostic(t *testing.T) {
	got := redactString("wrong password or corrupted file")
	if got != "wrong password or corrupted file" {
		t.Fatalf("diagnostic = %q", got)
	}
}

func TestRedactErrorCoversSecretBearingPaths(t *testing.T) {
	got := redactError(&os.PathError{Op: "open", Path: "/tmp/password=hunter2", Err: os.ErrNotExist})
	if strings.Contains(got, "hunter2") {
		t.Fatalf("redacted path still contains secret: %q", got)
	}
}
