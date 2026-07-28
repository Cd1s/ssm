package ssh

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func TestRunTraceRedactsDiagnosticWithoutChangingSuccessMetadata(t *testing.T) {
	const command = "printf 'token=TRACE_TOKEN_CANARY'"
	t.Setenv("SSM_TRACE", "1")
	var result RunResult
	stdout, stderr := captureHumanWriterOutput(t, func() {
		result = Run(config.Connection{
			Name: "plan", Host: "192.0.2.1", User: "root",
		}, &config.Vault{}, RunOptions{
			Command: command, Mode: "shell_command", PlanOnly: true,
		})
	})
	if stdout != "" || strings.Contains(stderr, "TRACE_TOKEN_CANARY") {
		t.Fatalf("trace stdout=%q stderr=%q", stdout, stderr)
	}
	if result.RemoteCommand != command {
		t.Fatalf("remote command=%q, want=%q", result.RemoteCommand, command)
	}
}

func TestRunSuccessWriterPreservesRemoteOutput(t *testing.T) {
	const remoteOutput = "token=<tokentoken ' exact>\n"

	t.Run("human", func(t *testing.T) {
		stdout, stderr := captureHumanWriterOutput(t, func() {
			WriteRunResult(RunResult{
				OK: true, Alias: "host", Exit: 0, Stdout: remoteOutput,
			}, false)
		})
		if !strings.Contains(stdout, "stdout="+strings.ReplaceAll(remoteOutput, "\n", "\\n")+"\n") || stderr != "" {
			t.Fatalf("stdout=%q stderr=%q, want successful remote output unchanged", stdout, stderr)
		}
	})

	t.Run("json", func(t *testing.T) {
		stdout, stderr := captureHumanWriterOutput(t, func() {
			WriteRunResult(RunResult{
				OK: true, Alias: "host", Exit: 0, Stdout: remoteOutput,
			}, true)
		})
		var result RunResult
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			t.Fatal(err)
		}
		if result.Stdout != remoteOutput || stderr != "" {
			t.Fatalf("stdout=%q stderr=%q, decoded remote stdout=%q want=%q", stdout, stderr, result.Stdout, remoteOutput)
		}
	})

	t.Run("ndjson", func(t *testing.T) {
		var output bytes.Buffer
		if err := WriteRunResultNDJSON(&output, RunResult{
			OK: true, Alias: "host", Exit: 0, Stdout: remoteOutput,
		}); err != nil {
			t.Fatal(err)
		}
		var result RunResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Stdout != remoteOutput {
			t.Fatalf("decoded remote stdout=%q want=%q", result.Stdout, remoteOutput)
		}
	})
}

func TestTypedSuccessWritersPreservePayloads(t *testing.T) {
	tests := []struct {
		name   string
		canary string
		write  func(bool)
	}{
		{
			name:   "check",
			canary: "CHECK_SUCCESS_CANARY",
			write: func(asJSON bool) {
				WriteCheckResult(CheckResult{
					OK: true, Alias: "host", Hostname: "token=CHECK_SUCCESS_CANARY",
				}, asJSON)
			},
		},
		{
			name:   "doctor",
			canary: "DOCTOR_SUCCESS_CANARY",
			write: func(asJSON bool) {
				WriteDoctorReport(DoctorReport{
					OK: true, Deep: map[string]string{"remote": "token=DOCTOR_SUCCESS_CANARY"},
				}, asJSON)
			},
		},
		{
			name:   "map",
			canary: "MAP_SUCCESS_CANARY",
			write: func(asJSON bool) {
				WriteMapResults([]RunResult{{
					OK: true, Alias: "host", Stdout: "token=MAP_SUCCESS_CANARY\n",
				}}, asJSON)
			},
		},
	}

	for _, test := range tests {
		for _, asJSON := range []bool{false, true} {
			format := "human"
			if asJSON {
				format = "json"
			}
			t.Run(test.name+"/"+format, func(t *testing.T) {
				stdout, stderr := captureHumanWriterOutput(t, func() {
					test.write(asJSON)
				})
				if !strings.Contains(stdout+stderr, test.canary) {
					t.Fatalf("%s success writer changed payload: stdout=%q stderr=%q", test.name, stdout, stderr)
				}
			})
		}
	}
}

func TestTypedFailureWritersRedactImmediatelyBeforeRendering(t *testing.T) {
	tests := []struct {
		name  string
		write func(bool)
	}{
		{
			name: "run",
			write: func(asJSON bool) {
				WriteRunResult(RunResult{
					OK: false, Alias: "host", Exit: 1,
					ResultMetadata: machinecontract.ResultMetadata{
						Error: "internal", Message: "token=RUN_TOKEN_CANARY",
					},
					Stdout:          "password=RUN_STDOUT_CANARY\nRUN_OPAQUE_CANARY",
					sensitiveValues: []string{"RUN_OPAQUE_CANARY"},
				}, asJSON)
			},
		},
		{
			name: "check",
			write: func(asJSON bool) {
				WriteCheckResult(CheckResult{
					OK: false, Alias: "host",
					Metadata: machinecontract.Metadata{
						Error: "internal", Message: "request_body=CHECK_REQUEST_CANARY", Exit: 1,
					},
				}, asJSON)
			},
		},
		{
			name: "doctor",
			write: func(asJSON bool) {
				WriteDoctorReport(DoctorReport{
					OK: false, Deep: map[string]string{"failure": "decrypted_inventory=DOCTOR_INVENTORY_CANARY"},
					Metadata: machinecontract.Metadata{
						Error: "internal", Message: "config=DOCTOR_CONFIG_CANARY", Exit: 1,
					},
				}, asJSON)
			},
		},
		{
			name: "map",
			write: func(asJSON bool) {
				WriteMapResults([]RunResult{{
					OK: false, Alias: "host", Exit: 1,
					ResultMetadata: machinecontract.ResultMetadata{Error: "internal"},
					Stdout:         "passphrase=MAP_STDOUT_CANARY",
					Stderr:         "private_key=MAP_STDERR_CANARY",
				}}, asJSON)
			},
		},
	}

	for _, test := range tests {
		for _, asJSON := range []bool{false, true} {
			format := "human"
			if asJSON {
				format = "json"
			}
			t.Run(test.name+"/"+format, func(t *testing.T) {
				stdout, stderr := captureHumanWriterOutput(t, func() {
					test.write(asJSON)
				})
				output := stdout + stderr
				if strings.Contains(output, "_CANARY") {
					t.Fatalf("%s %s failure writer leaked secret-shaped data: %q", test.name, format, output)
				}
			})
		}
	}
}

func TestRunFailureNDJSONRedactsKnownValues(t *testing.T) {
	var output bytes.Buffer
	if err := WriteRunResultNDJSON(&output, RunResult{
		OK: false, Alias: "host", Exit: 1,
		ResultMetadata: machinecontract.ResultMetadata{
			Error: "internal", Message: "RUN_OPAQUE_CANARY",
		},
		Stdout:          "RUN_OPAQUE_CANARY",
		sensitiveValues: []string{"RUN_OPAQUE_CANARY"},
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "RUN_OPAQUE_CANARY") {
		t.Fatalf("run NDJSON failure leaked known value: %q", output.String())
	}
}

func captureHumanWriterOutput(t *testing.T, write func()) (string, string) {
	t.Helper()

	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	t.Cleanup(func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
	})

	write()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr

	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatal(err)
	}
	return string(stdout), string(stderr)
}
