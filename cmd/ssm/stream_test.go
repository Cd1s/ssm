package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	"ssm/internal/ssh"
)

func TestParseRunStreamArgs(t *testing.T) {
	opts, stream, err := parseRunStreamArgs([]string{"--json", "--stream", "--refresh", "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if !stream || opts.refresh != 5*time.Second {
		t.Fatalf("stream=%t opts=%+v", stream, opts)
	}

	opts, stream, err = parseRunStreamArgs([]string{"--stream", "--refresh=0"})
	if err != nil || !stream || opts.refresh != 0 {
		t.Fatalf("zero refresh: stream=%t opts=%+v err=%v", stream, opts, err)
	}

	for _, args := range [][]string{
		{"--argv", "--stream"},
		{"--", "--stream"},
		{"hostname"},
	} {
		if _, stream, err := parseRunStreamArgs(args); err != nil || stream {
			t.Fatalf("normal run args %v recognized as stream: stream=%t err=%v", args, stream, err)
		}
	}
}

func TestDecodeArgvStreamLinePreservesArguments(t *testing.T) {
	got, err := decodeArgvStreamLine([]byte(`["printf","%s\n","space and ' quote"]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"printf", "%s\n", "space and ' quote"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv=%#v, want %#v", got, want)
	}

	for _, body := range []string{
		`[]`,
		`["true"] {}`,
		`{"argv":["true"]}`,
		`["before\u0000after"]`,
	} {
		if _, err := decodeArgvStreamLine([]byte(body)); err == nil {
			t.Fatalf("accepted invalid stream line %s", body)
		}
	}
}

func TestRunArgvStreamUsesStableNDJSONErrors(t *testing.T) {
	oldOffline, oldVault, oldPass := offlineMode, unlockedVault, masterPass
	t.Cleanup(func() {
		offlineMode, unlockedVault, masterPass = oldOffline, oldVault, oldPass
	})
	offlineMode = true
	unlockedVault = &config.Vault{}
	masterPass = "unused"

	var output bytes.Buffer
	exit := runArgvStream("missing", runStreamOptions{refresh: defaultStreamRefresh}, bytes.NewBufferString("{bad}\n[\"true\"]\n"), &output)
	if exit != machinecontract.ExitConnectionFailed {
		t.Fatalf("exit=%d", exit)
	}
	decoder := json.NewDecoder(&output)
	var invalid machinecontract.Failure
	if err := decoder.Decode(&invalid); err != nil {
		t.Fatal(err)
	}
	if invalid.OK || invalid.Error != "invalid_request" || invalid.Stage != "decode" {
		t.Fatalf("invalid result=%+v", invalid)
	}
	var missing ssh.RunResult
	if err := decoder.Decode(&missing); err != nil {
		t.Fatal(err)
	}
	if missing.OK || missing.Error != machinecontract.CodeAliasNotFound || missing.Stage != "lookup" {
		t.Fatalf("missing result=%+v", missing)
	}
}
