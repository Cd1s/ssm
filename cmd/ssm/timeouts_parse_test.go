package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseRemoteRunArgsConnectAndExecTimeouts(t *testing.T) {
	spec, err := parseRemoteRunArgs([]string{"--connect-timeout", "5s", "--exec-timeout", "2m", "--argv", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.ConnectTimeout != 5*time.Second || spec.ExecTimeout != 2*time.Minute || spec.Timeout != 0 || !strings.Contains(spec.Command, "true") {
		t.Fatalf("spec = %+v", spec)
	}
	spec, err = parseRemoteRunArgs([]string{"--connect-timeout=7", "--exec-timeout=90", "hostname"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.ConnectTimeout != 7*time.Second || spec.ExecTimeout != 90*time.Second {
		t.Fatalf("spec = %+v", spec)
	}
	// --timeout remains the compatible connect-timeout alias.
	spec, err = parseRemoteRunArgs([]string{"--timeout", "10s", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Timeout != 10*time.Second || spec.ExecTimeout != 0 {
		t.Fatalf("--timeout alias spec = %+v", spec)
	}
}

func TestParseRemoteRunArgsRejectsBadTimeouts(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--exec-timeout"}, "--exec-timeout requires a duration"},
		{[]string{"--exec-timeout", "0", "true"}, "--exec-timeout"},
		{[]string{"--exec-timeout=-5s", "true"}, "--exec-timeout must be positive"},
		{[]string{"--exec-timeout", "soon", "true"}, "invalid --exec-timeout"},
		{[]string{"--connect-timeout"}, "--connect-timeout requires a duration"},
		{[]string{"--connect-timeout=nope", "true"}, "invalid --connect-timeout"},
	} {
		_, err := parseRemoteRunArgs(test.args)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("parseRemoteRunArgs(%q) error = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestRunOptionTableRegistersTimeoutOptions(t *testing.T) {
	for _, option := range []string{"--connect-timeout", "--exec-timeout", "--timeout"} {
		if !runOptionTakesValue(option) {
			t.Fatalf("%s must consume its value in remoteArgvStart", option)
		}
	}
	// Values of the new options must not be mistaken for the remote argv.
	if got := remoteArgvStart([]string{"--exec-timeout", "5s", "--connect-timeout", "3s", "--argv", "x"}); got != 4 {
		t.Fatalf("remoteArgvStart = %d, want 4", got)
	}
	// After --argv the words belong to the remote program untouched.
	spec, err := parseRemoteRunArgs([]string{"--argv", "sleep", "--exec-timeout", "5"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.ExecTimeout != 0 || !strings.Contains(spec.Command, "--exec-timeout") {
		t.Fatalf("remote argv option was parsed by sshctl: %+v", spec)
	}
}

func TestApplyRunSpecEnvExportsConnectTimeout(t *testing.T) {
	t.Setenv("SSM_CONNECT_TIMEOUT", "")
	t.Setenv("SSM_TIMEOUT", "")
	applyRunSpecEnv(remoteRunSpec{ConnectTimeout: 4 * time.Second})
	if got := os.Getenv("SSM_CONNECT_TIMEOUT"); got != "4s" {
		t.Fatalf("SSM_CONNECT_TIMEOUT = %q", got)
	}
	applyRunSpecEnv(remoteRunSpec{Timeout: 6 * time.Second})
	if got := os.Getenv("SSM_TIMEOUT"); got != "6s" {
		t.Fatalf("SSM_TIMEOUT = %q", got)
	}
}

func TestParseRunStreamArgsTimeouts(t *testing.T) {
	options, stream, err := parseRunStreamArgs([]string{"--stream", "--exec-timeout", "3s", "--connect-timeout=4s", "--refresh", "0"})
	if err != nil || !stream {
		t.Fatalf("stream=%v err=%v", stream, err)
	}
	if options.execTimeout != 3*time.Second || options.connectTimeout != 4*time.Second || options.refresh != 0 {
		t.Fatalf("options = %+v", options)
	}
	if _, _, err := parseRunStreamArgs([]string{"--stream", "--exec-timeout", "0"}); err == nil {
		t.Fatal("zero --exec-timeout must be rejected")
	}
}

func TestRequestRunSpecExecTimeout(t *testing.T) {
	spec, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "a", Argv: []string{"true"}, ExecTimeout: "45s"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.ExecTimeout != 45*time.Second {
		t.Fatalf("spec = %+v", spec)
	}
	if _, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "a", Argv: []string{"true"}, ExecTimeout: "-1s"}); err == nil {
		t.Fatal("negative exec_timeout accepted")
	}
	if !hasRunRequestFields(agentRequest{ExecTimeout: "5s"}) {
		t.Fatal("exec_timeout must count as a run field so check/host requests reject it")
	}
}
