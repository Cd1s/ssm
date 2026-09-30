package machinecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// TestClassifySSHTransportErrorsNeverFallBackToInternal is the regression guard
// for issue #79: an SSH-layer error must map to a stable transport code, and
// "internal" stays reserved for genuine program errors.
func TestClassifySSHTransportErrorsNeverFallBackToInternal(t *testing.T) {
	t.Parallel()

	resetErr := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	dialContext := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: "dial"}
	sessionContext := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: "session"}
	acquireContext := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: "session", SessionAcquisition: true}
	bareContext := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22}

	tests := []struct {
		name    string
		err     error
		context SSHContext
		code    string
		stage   string
		outcome string
	}{
		{"exit missing", &gossh.ExitMissingError{}, sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exit missing wrapped", fmt.Errorf("wait: %w", &gossh.ExitMissingError{}), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exit missing message only", errors.New("wait: remote command exited without exit status or exit signal"), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec io.EOF", io.EOF, sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec unexpected EOF", io.ErrUnexpectedEOF, sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec connection reset", resetErr, sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec connection reset text", errors.New("read tcp 192.0.2.2:1->192.0.2.1:22: read: connection reset by peer"), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec broken pipe", os.NewSyscallError("write", syscall.EPIPE), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec closed socket", net.ErrClosed, sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec closed socket text", errors.New("write tcp 192.0.2.2:1->192.0.2.1:22: use of closed network connection"), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec ssh disconnect", errors.New("ssh: disconnect, reason 11: Connection closed by remote host"), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"exec windows forced close", errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"transfer-phase EOF", io.EOF, SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, ExecPhase: true}, CodeConnectionLost, "remote_execution", "unknown"},
		{"windows connection aborted text", errors.New("wsarecv: An established connection was aborted by the software in your host machine."), sessionContext, CodeConnectionLost, "remote_execution", "unknown"},
		{"windows connection reset text", errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), bareContext, CodeConnectionLost, "remote_execution", "unknown"},

		{"handshake EOF", errors.New("ssh: handshake failed: EOF"), dialContext, CodeHandshakeFailed, "handshake", ""},
		{"handshake EOF without stage", fmt.Errorf("ssh: handshake failed: %w", io.EOF), bareContext, CodeHandshakeFailed, "handshake", ""},
		{"handshake reset", fmt.Errorf("ssh: handshake failed: %w", resetErr), dialContext, CodeHandshakeFailed, "handshake", ""},
		{"handshake reset text", errors.New("ssh: handshake failed: read tcp 192.0.2.2:1->192.0.2.1:22: read: connection reset by peer"), dialContext, CodeHandshakeFailed, "handshake", ""},
		{"handshake protocol error", errors.New("ssh: handshake failed: ssh: overflow reading version string"), dialContext, CodeHandshakeFailed, "handshake", ""},
		{"handshake kex failure", errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange; client offered: [a], server offered: [b]"), dialContext, CodeHandshakeFailed, "handshake", ""},
		{"handshake server disconnect", errors.New("ssh: handshake failed: ssh: disconnect, reason 2: Protocol error"), dialContext, CodeHandshakeFailed, "handshake", ""},

		{"session channel rejected typed", &gossh.OpenChannelError{Reason: gossh.ResourceShortage, Message: "open failed"}, bareContext, CodeSession, "", ""},
		{"session channel rejected pinned text", errors.New(`ssh: rejected: resource shortage ("fixture session rejected")`), bareContext, CodeSession, "", ""},
		{"session limit typed", &gossh.OpenChannelError{Reason: gossh.Prohibited, Message: "open failed"}, acquireContext, CodeSessionLimit, "session", ""},
		{"session limit typed wrapped", fmt.Errorf("session: %w", &gossh.OpenChannelError{Reason: gossh.Prohibited, Message: "open failed"}), acquireContext, CodeSessionLimit, "session", ""},
		{"other open failed text is not a session limit", errors.New("ssh: rejected: connect failed (open failed)"), acquireContext, CodeSession, "session", ""},
		{"unknown channel type is not a session limit", &gossh.OpenChannelError{Reason: gossh.UnknownChannelType, Message: "open failed"}, acquireContext, CodeSession, "session", ""},
		{"session acquisition EOF keeps session_failed", io.EOF, acquireContext, CodeSession, "session", ""},

		// Classifications that predate #79 keep priority over the new branches.
		{"auth failure", errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"), dialContext, CodeAuth, "dial", ""},
		{"no auth configured", errors.New("no authentication configured"), dialContext, CodeNoAuth, "dial", ""},
		{"host key mismatch text", errors.New("ssh: handshake failed: knownhosts: key mismatch"), dialContext, CodeHostKey, "dial", ""},
		// #73: a handshake that stalls until the connect deadline is a
		// handshake failure (TCP connected, no command sent), not a dial
		// timeout. Only the typed deadline error moves; the untyped text stays
		// pinned to the historical dial_timeout tuple below.
		{"handshake timeout text stays historical", errors.New("ssh: handshake failed: timeout"), dialContext, CodeDialTimeout, "dial", ""},
		{"handshake deadline typed", fmt.Errorf("ssh: handshake failed: %w", &net.OpError{Op: "read", Net: "tcp", Err: handshakeDeadlineError{}}), dialContext, CodeHandshakeFailed, "handshake", ""},
		{"tcp dial timeout stays dial_timeout", &net.OpError{Op: "dial", Net: "tcp", Err: handshakeDeadlineError{}}, dialContext, CodeDialTimeout, "dial", ""},
		{"connection refused", errors.New("dial tcp 192.0.2.1:22: connect: connection refused"), dialContext, CodeDialRefused, "dial", ""},
		{"no route", errors.New("dial tcp 192.0.2.1:22: connect: no route to host"), dialContext, CodeDialNetwork, "dial", ""},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifySSH(test.err, test.context)
			if got.Error == CodeInternal {
				t.Fatalf("ClassifySSH(%v) fell back to internal: %+v", test.err, got)
			}
			if got.Error != test.code || got.Outcome != test.outcome || (test.stage != "" && got.Stage != test.stage) {
				t.Fatalf("ClassifySSH(%v) = %+v, want code=%s stage=%q outcome=%q", test.err, got, test.code, test.stage, test.outcome)
			}
			if got.Exit != ExitConnectionFailed || ProcessExit(got) != ExitConnectionFailed {
				t.Fatalf("ClassifySSH(%v) exit=%d process=%d, want 255", test.err, got.Exit, ProcessExit(got))
			}
			if got.Error != CodeConnectionLost && got.Outcome != "" {
				t.Fatalf("outcome %q must appear only on connection_lost: %+v", got.Outcome, got)
			}
		})
	}
}

// TestClassifySSHBareEOFOutsideExecutionStaysInternal guards against the EOF
// matcher swallowing non-transport errors, such as a truncated private key.
func TestClassifySSHBareEOFOutsideExecutionStaysInternal(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		io.EOF,
		fmt.Errorf("parse private key: %w", io.ErrUnexpectedEOF),
		errors.New("ssh: no key found: EOF"),
		errors.New("EOF"),
	} {
		for _, stage := range []string{"", "dial"} {
			got := ClassifySSH(err, SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: stage})
			if got.Error != CodeInternal {
				t.Fatalf("ClassifySSH(%v, stage %q) = %+v, want internal", err, stage, got)
			}
		}
	}
}

func TestClassifyTransferKeepsTransportStageAndExit(t *testing.T) {
	t.Parallel()
	context := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22}
	handshake := errors.New("ssh: handshake failed: EOF")
	for name, classify := range map[string]func(error, Failure) Failure{
		"put": func(err error, carried Failure) Failure { return ClassifyTransferOperation(err, context, carried) },
		"get": func(err error, _ Failure) Failure { return ClassifyDownload(err, context) },
	} {
		got := classify(handshake, Failure{})
		if got.Error != CodeHandshakeFailed || got.Stage != "handshake" || got.Outcome != "" || got.Exit != ExitConnectionFailed || ProcessExit(got) != ExitConnectionFailed {
			t.Fatalf("%s handshake = %+v", name, got)
		}
		for _, kind := range []Kind{TransferTimedOut, ResumeTimedOut} {
			for _, cause := range []error{io.EOF, &gossh.ExitMissingError{}} {
				timeout := Classify(kind, Details{Cause: cause})
				got = classify(&testTransferFailureCarrier{failure: timeout, cause: cause}, timeout)
				if got.Error != "transfer_timeout" || got.Stage != "timeout" || got.Outcome != "" || got.Exit != 1 || ProcessExit(got) != 1 {
					t.Fatalf("%s %s with %v = %+v, want transfer_timeout/exit 1/no outcome", name, kind, cause, got)
				}
			}
		}
		carried := Classify(TransferRemoteWriteFailed, Details{Cause: io.EOF})
		got = classify(fmt.Errorf("transfer: %w", &gossh.ExitMissingError{}), carried)
		if got.Error != CodeConnectionLost || got.Stage != "remote_execution" || got.Outcome != "unknown" || got.Exit != ExitConnectionFailed || ProcessExit(got) != ExitConnectionFailed {
			t.Fatalf("%s connection lost = %+v", name, got)
		}
	}
}

// TestClassifySSHKeepsInternalForProgramErrors documents what internal is
// still for: errors with no SSH-transport signature.
func TestClassifySSHKeepsInternalForProgramErrors(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		errors.New("unexpected failure"),
		errors.New("json: cannot unmarshal string into Go value"),
		errors.New("index out of range"),
	} {
		got := ClassifySSH(err, SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: "session"})
		if got.Error != CodeInternal || got.Exit != 1 || got.Outcome != "" {
			t.Fatalf("ClassifySSH(%v) = %+v, want internal/exit 1", err, got)
		}
	}
}

func TestClassifySSHKeepsPolicyStageForClassifiedErrors(t *testing.T) {
	t.Parallel()
	// The dial adapter classifies before the caller knows its stage; a caller
	// stage of "dial" or "session" must not erase what the code means.
	handshake := NewClassifiedError(Classify(HandshakeFailed, Details{Message: "ssh: handshake failed: EOF"}))
	if got := ClassifySSH(handshake, SSHContext{Stage: "dial"}); got.Error != CodeHandshakeFailed || got.Stage != "handshake" {
		t.Fatalf("classified handshake = %+v", got)
	}
	lost := NewClassifiedError(Classify(ConnectionLost, Details{Message: "eof"}))
	if got := ClassifySSH(lost, SSHContext{Stage: "session"}); got.Error != CodeConnectionLost || got.Stage != "remote_execution" || got.Outcome != "unknown" {
		t.Fatalf("classified connection_lost = %+v", got)
	}
}

// Specific diagnoses reached from the remote result or from sshctl itself must
// survive a transport error that accompanies them (for example the abort or
// reset a closing channel produces on Windows), while generic wrapper codes
// yield to connection_lost.
func TestClassifyTransferCarriedDiagnosisBeatsTransportError(t *testing.T) {
	t.Parallel()
	context := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22}
	causes := map[string]error{
		"forcibly closed text": errors.New("wsarecv: An existing connection was forcibly closed by the remote host."),
		"aborted text":         errors.New("wsarecv: An established connection was aborted by the software in your host machine."),
		"ECONNRESET":           os.NewSyscallError("write", syscall.ECONNRESET),
		"EOF":                  io.EOF,
		"exit missing":         &gossh.ExitMissingError{},
	}
	specific := []struct {
		kind Kind
		code string
		exit int
	}{
		{IntegrityToolUnavailable, "integrity_tool_unavailable", 1},
		{TransferRemoteExtractFailed, "remote_write_failed", 1},
		{TransferRemotePermissionsFailed, "remote_write_failed", 1},
		{TransferIntegrityMismatch, "integrity_failed", 1},
		{TransferReceiptInvalid, "integrity_failed", 1},
		{TransferTimedOut, "transfer_timeout", 1},
		{ResumeTimedOut, "transfer_timeout", 1},
		{TransferDownloadLocalWrite, "local_write_failed", 1},
		{TransferDownloadIntegrityMismatch, "integrity_failed", 1},
		{TransferLocalRead, "local_read_failed", 1},
		{TransferDirectoryOptionsUnsupported, "unsupported_transfer_option", 1},
	}
	wrappers := []Kind{
		TransferSessionOpenFailed, TransferStdinOpenFailed, TransferStartFailed, TransferRemoteWriteFailed,
		TransferRemoteCloseFailed, ResumeStdinOpenFailed, ResumeStartFailed, ResumeRemoteWriteFailed,
		ResumeRetryFailed, ResumeProbeSessionFailed, TransferDownloadRemoteRead,
	}
	for name, cause := range causes {
		for _, test := range specific {
			carried := Classify(test.kind, Details{Cause: cause})
			carrier := &testTransferFailureCarrier{failure: carried, cause: cause}
			for direction, got := range map[string]Failure{
				"put": ClassifyTransferOperation(carrier, context, carried),
				"get": ClassifyDownload(carrier, context),
			} {
				if got.Error != test.code || got.Outcome != "" || got.Exit != test.exit || ProcessExit(got) != test.exit {
					t.Errorf("%s %s with %s = %+v, want %s exit %d", direction, test.kind, name, got, test.code, test.exit)
				}
			}
		}
		for _, kind := range wrappers {
			carried := Classify(kind, Details{Cause: cause})
			carrier := &testTransferFailureCarrier{failure: carried, cause: cause}
			for direction, got := range map[string]Failure{
				"put": ClassifyTransferOperation(carrier, context, carried),
				"get": ClassifyDownload(carrier, context),
			} {
				if got.Error != CodeConnectionLost || got.Outcome != "unknown" || got.Exit != ExitConnectionFailed {
					t.Errorf("%s wrapper %s with %s = %+v, want connection_lost/255", direction, kind, name, got)
				}
			}
		}
	}
}

func TestClassifySSHTransportOutcomeSerialization(t *testing.T) {
	t.Parallel()
	context := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: "session"}
	lost := ClassifySSH(&gossh.ExitMissingError{}, context)
	handshake := ClassifySSH(errors.New("ssh: handshake failed: EOF"), SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: "dial"})

	var machine bytes.Buffer
	if err := RenderFailure(NDJSON, Streams{Stdout: &machine}, lost); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["error"] != "connection_lost" || decoded["outcome"] != "unknown" || decoded["stage"] != "remote_execution" || decoded["exit"] != float64(255) {
		t.Fatalf("connection_lost JSON = %s", machine.String())
	}

	machine.Reset()
	if err := RenderFailure(NDJSON, Streams{Stdout: &machine}, handshake); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(machine.String(), "outcome") || !strings.Contains(machine.String(), `"stage":"handshake"`) {
		t.Fatalf("handshake_failed JSON = %s", machine.String())
	}

	var human bytes.Buffer
	if err := RenderFailure(Human, Streams{Stderr: &human}, lost); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(human.String(), "ssm: error=connection_lost stage=remote_execution outcome=unknown alias=prod") {
		t.Fatalf("connection_lost human = %q", human.String())
	}
}

type handshakeDeadlineError struct{}

func (handshakeDeadlineError) Error() string   { return "i/o timeout" }
func (handshakeDeadlineError) Timeout() bool   { return true }
func (handshakeDeadlineError) Temporary() bool { return true }

// TestExecTimeoutClassificationIsNotOverwritten pins that an exec_timeout the
// run layer produced keeps its code, stage and exit when it passes through the
// SSH classifier again, so the EOF that follows sshctl closing its own session
// can never be reported as connection_lost.
func TestExecTimeoutClassificationIsNotOverwritten(t *testing.T) {
	t.Parallel()
	timeout := Classify(ExecTimedOut, Details{Message: "command exceeded --exec-timeout 2s", Alias: "prod"})
	got := ClassifySSH(NewClassifiedError(timeout), SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22, Stage: "session", ExecPhase: true})
	if got.Error != "exec_timeout" || got.Stage != "remote_execution" || got.Exit != 124 || got.Outcome != "" {
		t.Fatalf("classified exec_timeout = %+v", got)
	}
	if ProcessExit(got) != 124 {
		t.Fatalf("process exit = %d, want 124", ProcessExit(got))
	}
}
