package machinecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

type issue17FixtureRow struct {
	Name        string   `json:"name"`
	Error       string   `json:"error"`
	Stage       string   `json:"stage,omitempty"`
	JSONExit    int      `json:"json_exit"`
	ProcessExit int      `json:"process_exit"`
	Hint        string   `json:"hint,omitempty"`
	Alias       string   `json:"alias,omitempty"`
	Candidates  []string `json:"candidates,omitempty"`
	Absent      []string `json:"absent,omitempty"`
	Cardinality string   `json:"cardinality"`
}

type issue17RenderCase struct {
	failure      Failure
	machineMode  Format
	machine      any
	machineAlias string
	wantMachine  string
	wantHuman    string
}

func TestIssue17ReviewedFailureRenderingMatrix(t *testing.T) {
	rows := loadIssue17FixtureRows(t)
	cases := issue17RenderCases()
	if len(cases) != len(rows) {
		t.Fatalf("render cases = %d, reviewed #17 rows = %d", len(cases), len(rows))
	}

	for name, row := range rows {
		test, ok := cases[name]
		if !ok {
			t.Fatalf("reviewed #17 failure %q has no human+machine acceptance case", name)
		}
		t.Run(name, func(t *testing.T) {
			failure := test.failure
			alias := failure.Alias
			if test.machineAlias != "" {
				alias = test.machineAlias
			}
			if failure.Error != row.Error || failure.Stage != row.Stage ||
				failure.Exit != row.JSONExit || ProcessExit(failure) != row.ProcessExit ||
				failure.Hint != row.Hint || alias != row.Alias ||
				!reflect.DeepEqual(failure.Candidates, row.Candidates) {
				t.Fatalf("classified failure = %+v, reviewed row = %+v, process exit = %d", failure, row, ProcessExit(failure))
			}

			var machineStdout, machineStderr bytes.Buffer
			if err := RenderFailure(test.machineMode, Streams{Stdout: &machineStdout, Stderr: &machineStderr}, test.machine); err != nil {
				t.Fatal(err)
			}
			if machineStdout.String() != test.wantMachine || machineStderr.Len() != 0 {
				t.Fatalf("machine stdout=%q stderr=%q, want stdout=%q", machineStdout.String(), machineStderr.String(), test.wantMachine)
			}
			value := decodeIssue17MachineValue(t, machineStdout.String(), row.Cardinality)
			for _, field := range row.Absent {
				if _, exists := value[field]; exists {
					t.Fatalf("machine field %q must be omitted from %s", field, machineStdout.String())
				}
			}
			if got, ok := value["exit"].(float64); !ok || int(got) != row.JSONExit {
				t.Fatalf("machine exit = %v, want %d", value["exit"], row.JSONExit)
			}

			var humanStdout, humanStderr bytes.Buffer
			if err := Render(Human, Streams{Stdout: &humanStdout, Stderr: &humanStderr}, failure); err != nil {
				t.Fatal(err)
			}
			if humanStdout.Len() != 0 || humanStderr.String() != test.wantHuman {
				t.Fatalf("human stdout=%q stderr=%q, want stderr=%q", humanStdout.String(), humanStderr.String(), test.wantHuman)
			}
		})
	}
}

func TestIssue17PreBC3StreamStartupUsesJSONDocument(t *testing.T) {
	failure := issue17RenderCases()["stream_refresh_failed"].failure
	var stdout, stderr bytes.Buffer
	if err := Render(JSONDocument, Streams{Stdout: &stdout, Stderr: &stderr}, failure); err != nil {
		t.Fatal(err)
	}
	want := "{\n" +
		"  \"ok\": false,\n" +
		"  \"error\": \"sync_pull_failed\",\n" +
		"  \"message\": \"sync endpoint failed\",\n" +
		"  \"hint\": \"fix sync connectivity or restart explicitly with --offline\",\n" +
		"  \"stage\": \"sync_pull\",\n" +
		"  \"exit\": 1\n" +
		"}\n"
	if stdout.String() != want || stderr.Len() != 0 || strings.Count(strings.TrimSpace(stdout.String()), "\n") == 0 {
		t.Fatalf("pre-BC-3 startup stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func loadIssue17FixtureRows(t *testing.T) map[string]issue17FixtureRow {
	t.Helper()
	data, err := os.ReadFile("../../cmd/ssm/testdata/compiled_contracts/v1_failure_matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var rows []issue17FixtureRow
	if err := decoder.Decode(&rows); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("reviewed #17 fixture has trailing data: %v", err)
	}
	output := make(map[string]issue17FixtureRow, len(rows))
	for _, row := range rows {
		if _, duplicate := output[row.Name]; duplicate {
			t.Fatalf("duplicate reviewed #17 row %q", row.Name)
		}
		output[row.Name] = row
	}
	return output
}

func decodeIssue17MachineValue(t *testing.T, output, cardinality string) map[string]any {
	t.Helper()
	if cardinality == "one_line" && (strings.Count(output, "\n") != 1 || !strings.HasSuffix(output, "\n")) {
		t.Fatalf("NDJSON cardinality is not one line: %q", output)
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("machine cardinality is not exactly one JSON value: %q", output)
	}
	return value
}

func issue17RenderCases() map[string]issue17RenderCase {
	unknownSSHCTL := Classify(UnknownSSHCTLCommand, Details{Message: `unknown command "not-a-command"`})
	unknownSSM := Classify(UnknownSSMCommand, Details{Message: `unknown command "not-a-command"`})
	invalidRequest := Classify(InvalidRequestDocument, Details{Message: `json: unknown field "unexpected"`})
	unlockRequired := Classify(MasterPassFileRequiredCreate, Details{Message: "vault does not exist"})
	aliasMiss := Classify(AliasNotFound, Details{
		Message: `connection "prod" not found`, Alias: "prod", Candidates: []string{"prod-one", "prod-two"},
	})
	syncConflict := Classify(SyncConflict, Details{Message: "remote changed"})
	transferCause := errors.New("open artifact: file does not exist")
	transfer := ClassifyTransferOperation(
		transferCause,
		SSHContext{Alias: "transfer", Host: "192.0.2.1", Port: 22},
		Classify(TransferLocalRead, Details{Cause: transferCause}),
	)
	transferDocument := struct {
		OK bool `json:"ok"`
		TransferMetadata
		Alias     string `json:"alias"`
		BytesSent int64  `json:"bytes_sent"`
		Integrity string `json:"integrity"`
		Atomic    bool   `json:"atomic"`
		Resume    string `json:"resume"`
	}{
		OK: false, TransferMetadata: transfer.TransferMetadata(), Alias: "transfer",
		BytesSent: 0, Integrity: "not_checked", Atomic: false, Resume: "unsupported",
	}
	hostKeyUnknown := ClassifySSH(&knownhosts.KeyError{}, SSHContext{
		Alias: "host-key", Host: "127.0.0.1", Port: 22, Stage: "dial",
	})
	dialRefused := ClassifySSH(errors.New("connection refused"), SSHContext{
		Alias: "refused", Host: "127.0.0.1", Port: 22, Stage: "dial",
	})
	windowsMessage := "dial tcp 127.0.0.1:22: connectex: No connection could be made because the target machine actively refused it"
	windowsDial := ClassifySSH(errors.New(windowsMessage), SSHContext{
		Alias: "refused", Host: "127.0.0.1", Port: 22, Stage: "dial",
	})
	auth := ClassifySSH(errors.New("ssh: unable to authenticate"), SSHContext{
		Alias: "auth", Host: "127.0.0.1", Port: 22, Stage: "dial",
	})
	session := ClassifySSH(errors.New("ssh: rejected session"), SSHContext{
		Alias: "session", Host: "127.0.0.1", Port: 22, Stage: "session", SessionAcquisition: true,
	})
	remote255 := Classify(RemoteCommandFailed, Details{
		Message: "remote command exited non-zero", Alias: "remote-255", Exit: 255,
	})
	stream := Classify(StreamSyncPullFailed, Details{Message: "sync endpoint failed"})

	return map[string]issue17RenderCase{
		"unknown_sshctl": {
			failure: unknownSSHCTL, machineMode: JSONDocument, machine: unknownSSHCTL,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"unknown_command\",\n  \"message\": \"unknown command \\\"not-a-command\\\"\",\n  \"hint\": \"use sshctl run \\u003calias\\u003e --argv \\u003ccommand\\u003e or sshctl --help\",\n  \"exit\": 2\n}\n",
			wantHuman:   "ssm: error=unknown_command\nError: unknown command \"not-a-command\"\nssm: hint=use sshctl run <alias> --argv <command> or sshctl --help\n",
		},
		"unknown_ssm": {
			failure: unknownSSM, machineMode: JSONDocument, machine: unknownSSM,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"unknown_command\",\n  \"message\": \"unknown command \\\"not-a-command\\\"\",\n  \"hint\": \"use ssm --help for available commands\",\n  \"exit\": 2\n}\n",
			wantHuman:   "ssm: error=unknown_command\nError: unknown command \"not-a-command\"\nssm: hint=use ssm --help for available commands\n",
		},
		"invalid_request_unknown_field": {
			failure: invalidRequest, machineMode: JSONDocument, machine: invalidRequest,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"invalid_request\",\n  \"message\": \"json: unknown field \\\"unexpected\\\"\",\n  \"hint\": \"use schema version 1 and exactly one typed operation\",\n  \"exit\": 2\n}\n",
			wantHuman:   "ssm: error=invalid_request\nError: json: unknown field \"unexpected\"\nssm: hint=use schema version 1 and exactly one typed operation\n",
		},
		"unlock_file_required": {
			failure: unlockRequired, machineMode: JSONDocument, machine: unlockRequired,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"master_pass_file_required\",\n  \"message\": \"vault does not exist\",\n  \"hint\": \"provide --master-pass-file or SSM_MASTER_PASS_FILE to create it non-interactively\",\n  \"exit\": 2\n}\n",
			wantHuman:   "ssm: error=master_pass_file_required\nError: vault does not exist\nssm: hint=provide --master-pass-file or SSM_MASTER_PASS_FILE to create it non-interactively\n",
		},
		"exact_alias_miss": {
			failure: aliasMiss, machineMode: JSONDocument, machine: aliasMiss,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"alias_not_found\",\n  \"message\": \"connection \\\"prod\\\" not found\",\n  \"hint\": \"use sshctl host list --json and retry with an exact alias\",\n  \"alias\": \"prod\",\n  \"exit\": 255,\n  \"candidates\": [\n    \"prod-one\",\n    \"prod-two\"\n  ]\n}\n",
			wantHuman:   "ssm: error=alias_not_found alias=prod\nConnection \"prod\" not found.\nssm: did_you_mean=prod-one,prod-two\nDid you mean: prod-one, prod-two\nssm: hint=use sshctl host list --json; or ssm redirect set <old> <new> after migration\n",
		},
		"sync_etag_conflict": {
			failure: syncConflict, machineMode: JSONDocument, machine: syncConflict,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"sync_conflict\",\n  \"message\": \"remote changed\",\n  \"hint\": \"local and remote blobs were preserved; inspect sshctl --offline --json doctor, then run sshctl --json pull after review\",\n  \"stage\": \"sync_compare\",\n  \"exit\": 1\n}\n",
			wantHuman:   "ssm: error=sync_conflict stage=sync_compare\nError: remote changed\nssm: hint=local and remote blobs were preserved; inspect sshctl --offline --json doctor, then run sshctl --json pull after review\n",
		},
		"transfer_local_read": {
			failure: transfer, machineMode: JSONDocument, machine: transferDocument, machineAlias: "transfer",
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"local_read_failed\",\n  \"message\": \"open artifact: file does not exist\",\n  \"hint\": \"verify the local path and read permissions\",\n  \"exit\": 1,\n  \"stage\": \"local_read\",\n  \"alias\": \"transfer\",\n  \"bytes_sent\": 0,\n  \"integrity\": \"not_checked\",\n  \"atomic\": false,\n  \"resume\": \"unsupported\"\n}\n",
			wantHuman:   "ssm: error=internal alias=transfer address=192.0.2.1:22\nError: open artifact: file does not exist\n",
		},
		"host_key_unknown": {
			failure: hostKeyUnknown, machineMode: JSONDocument, machine: hostKeyUnknown,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"host_key_unknown\",\n  \"message\": \"remote host key is not trusted yet\",\n  \"hint\": \"run sshctl host-key inspect \\u003calias\\u003e --json, verify the observed fingerprint through a trusted channel, then use fingerprint-bound host-key accept\",\n  \"stage\": \"dial\",\n  \"alias\": \"host-key\",\n  \"exit\": 255\n}\n",
			wantHuman:   "ssm: error=host_key_unknown stage=dial alias=host-key address=127.0.0.1:22\nError: remote host key is not trusted yet\nssm: hint=run sshctl host-key inspect <alias> --json, verify the observed fingerprint through a trusted channel, then use fingerprint-bound host-key accept\n",
		},
		"dial_refused": {
			failure: dialRefused, machineMode: JSONDocument, machine: dialRefused,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"dial_refused\",\n  \"message\": \"connection refused by 127.0.0.1:22\",\n  \"hint\": \"sshd not listening or wrong port; not an ssm quote bug\",\n  \"stage\": \"dial\",\n  \"alias\": \"refused\",\n  \"exit\": 255\n}\n",
			wantHuman:   "ssm: error=dial_refused stage=dial alias=refused address=127.0.0.1:22\nError: connection refused by 127.0.0.1:22\nssm: hint=sshd not listening or wrong port; not an ssm quote bug\n",
		},
		"dial_refused_windows": {
			failure: windowsDial, machineMode: JSONDocument, machine: windowsDial,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"internal\",\n  \"message\": \"" + windowsMessage + "\",\n  \"stage\": \"dial\",\n  \"alias\": \"refused\",\n  \"exit\": 255\n}\n",
			wantHuman:   "ssm: error=internal stage=dial alias=refused address=127.0.0.1:22\nError: " + windowsMessage + "\n",
		},
		"auth_failed": {
			failure: auth, machineMode: JSONDocument, machine: auth,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"auth_failed\",\n  \"message\": \"SSH authentication failed\",\n  \"hint\": \"check password/key in vault; not a quote or SSM client bug\",\n  \"stage\": \"dial\",\n  \"alias\": \"auth\",\n  \"exit\": 255\n}\n",
			wantHuman:   "ssm: error=auth_failed stage=dial alias=auth address=127.0.0.1:22\nError: SSH authentication failed\nssm: hint=check password/key in vault; not a quote or SSM client bug\n",
		},
		"session_failed": {
			failure: session, machineMode: JSONDocument, machine: session,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"session_failed\",\n  \"message\": \"ssh: rejected session\",\n  \"hint\": \"SSH connected but session failed; remote sshd or resources may be unhealthy\",\n  \"stage\": \"session\",\n  \"alias\": \"session\",\n  \"exit\": 255\n}\n",
			wantHuman:   "ssm: error=session_failed stage=session alias=session address=127.0.0.1:22\nError: ssh: rejected session\nssm: hint=SSH connected but session failed; remote sshd or resources may be unhealthy\n",
		},
		"remote_exit_255": {
			failure: remote255, machineMode: JSONDocument, machine: remote255,
			wantMachine: "{\n  \"ok\": false,\n  \"error\": \"remote_failed\",\n  \"message\": \"remote command exited non-zero\",\n  \"hint\": \"inspect stdout/stderr; SSH transport succeeded\",\n  \"stage\": \"remote_execution\",\n  \"alias\": \"remote-255\",\n  \"exit\": 255\n}\n",
			wantHuman:   "ssm: error=remote_failed stage=remote_execution alias=remote-255\nError: remote command exited non-zero\nssm: hint=inspect stdout/stderr; SSH transport succeeded\n",
		},
		"stream_refresh_failed": {
			failure: stream, machineMode: NDJSON, machine: stream,
			wantMachine: "{\"ok\":false,\"error\":\"sync_pull_failed\",\"message\":\"sync endpoint failed\",\"hint\":\"fix sync connectivity or restart explicitly with --offline\",\"stage\":\"sync_pull\",\"exit\":1}\n",
			wantHuman:   "ssm: error=sync_pull_failed stage=sync_pull\nError: sync endpoint failed\nssm: hint=fix sync connectivity or restart explicitly with --offline\n",
		},
	}
}
