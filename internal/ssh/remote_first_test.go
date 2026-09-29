package ssh

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/machinecontract"
)

type fakeWaitSession struct {
	waitErr error
	closed  bool
}

func (f *fakeWaitSession) Wait() error  { return f.waitErr }
func (f *fakeWaitSession) Close() error { f.closed = true; return nil }

// When the remote exits before reading its input (no SHA-256 tool), closing
// stdin can fail with EOF after every byte was written. The remote's marker,
// not that EOF, is the reason to report.
func TestCollectRemoteFirstPrefersRemoteMarkerOverStdinCloseError(t *testing.T) {
	t.Parallel()
	remoteExit := errors.New("remote exited 69")
	tests := []struct {
		name      string
		stdout    string
		waitErr   error
		timedOut  bool
		fallback  machinecontract.Kind
		wantCode  string
		wantStage string
		wantInteg string
	}{
		{"tool missing after close error", integrityToolMissingMarker + "\n", remoteExit, false, machinecontract.TransferRemoteCloseFailed, "integrity_tool_unavailable", "capability", ""},
		{"tool missing after copy error", integrityToolMissingMarker + "\n", remoteExit, false, machinecontract.TransferRemoteWriteFailed, "integrity_tool_unavailable", "capability", ""},
		{"integrity mismatch", "SSM_INTEGRITY_MISMATCH\n", remoteExit, false, machinecontract.TransferRemoteCloseFailed, "integrity_failed", "integrity", "mismatch"},
		{"no marker falls back to close failure", "", &gossh.ExitMissingError{}, false, machinecontract.TransferRemoteCloseFailed, "remote_write_failed", "remote_write", ""},
		{"marker without remote failure is ignored", integrityToolMissingMarker + "\n", nil, false, machinecontract.TransferRemoteCloseFailed, "remote_write_failed", "remote_write", ""},
		{"timeout wins", integrityToolMissingMarker + "\n", remoteExit, true, machinecontract.TransferRemoteCloseFailed, "transfer_timeout", "remote_write", ""},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			session := &fakeWaitSession{waitErr: test.waitErr}
			timedOut := new(atomic.Bool)
			timedOut.Store(test.timedOut)
			result := TransferResult{Stage: "remote_write"}
			var stdout bytes.Buffer
			stdout.WriteString(test.stdout)
			got := collectRemoteFirst(session, time.Second, &result, 20, timedOut, &stdout, io.EOF, test.fallback)
			failure := got.ContractFailure()
			if failure.Error != test.wantCode || got.BytesSent != 20 || !session.closed {
				t.Fatalf("failure = %+v bytes=%d closed=%v, want %s", failure, got.BytesSent, session.closed, test.wantCode)
			}
			if test.wantCode == "integrity_tool_unavailable" && (result.Stage != test.wantStage || failure.Exit != 1) {
				t.Fatalf("tool-missing stage=%q exit=%d, want capability/1", result.Stage, failure.Exit)
			}
			if test.wantInteg != "" && result.Integrity != test.wantInteg {
				t.Fatalf("integrity = %q, want %q", result.Integrity, test.wantInteg)
			}
		})
	}
}

func TestCollectResumeRemoteFirstPrefersRemoteMarker(t *testing.T) {
	t.Parallel()
	session := &fakeWaitSession{waitErr: errors.New("remote exited 69")}
	result := TransferResult{}
	var stdout bytes.Buffer
	stdout.WriteString("SSM_RESUME_ERROR tool_missing\n")
	got := collectResumeRemoteFirst(session, time.Second, &result, 7, new(atomic.Bool), &stdout, io.EOF, machinecontract.ResumeRetryFailed)
	if failure := got.ContractFailure(); failure.Error != "verification_tool_missing" {
		t.Fatalf("failure = %+v, want verification_tool_missing", failure)
	}
	stdout.Reset()
	got = collectResumeRemoteFirst(session, time.Second, &result, 7, new(atomic.Bool), &stdout, io.EOF, machinecontract.ResumeRetryFailed)
	if failure := got.ContractFailure(); failure.Error != "remote_write_failed" {
		t.Fatalf("no-marker failure = %+v, want remote_write_failed", failure)
	}
}

// blockingSession's Wait blocks until Close, like a live session whose remote
// never reports an exit status. onClose runs inside Close, like the --timeout
// timer closing the session.
type blockingSession struct {
	closed  chan struct{}
	once    atomic.Bool
	onClose func()
}

func newBlockingSession(onClose func()) *blockingSession {
	return &blockingSession{closed: make(chan struct{}), onClose: onClose}
}

func (b *blockingSession) Wait() error {
	<-b.closed
	return &gossh.ExitMissingError{}
}

func (b *blockingSession) Close() error {
	if b.once.CompareAndSwap(false, true) {
		if b.onClose != nil {
			b.onClose()
		}
		close(b.closed)
	}
	return nil
}

func TestCollectRemoteFirstBoundsTheWaitAndFallsBack(t *testing.T) {
	t.Parallel()
	session := newBlockingSession(nil)
	var stdout bytes.Buffer
	started := time.Now()
	got := collectRemoteFirst(session, 20*time.Millisecond, &TransferResult{}, 3, new(atomic.Bool), &stdout, io.EOF, machinecontract.TransferRemoteCloseFailed)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("bounded wait took %s", elapsed)
	}
	if failure := got.ContractFailure(); failure.Error != "remote_write_failed" {
		t.Fatalf("failure = %+v, want remote_write_failed fallback after grace", failure)
	}
}

// The --timeout timer can fire while the grace wait is running; the flag must
// be read after the wait, not captured before it.
func TestCollectRemoteFirstReadsTimeoutAfterTheWait(t *testing.T) {
	t.Parallel()
	timedOut := new(atomic.Bool)
	session := newBlockingSession(func() { timedOut.Store(true) })
	var stdout bytes.Buffer
	got := collectRemoteFirst(session, 20*time.Millisecond, &TransferResult{}, 3, timedOut, &stdout, io.EOF, machinecontract.TransferRemoteCloseFailed)
	if failure := got.ContractFailure(); failure.Error != "transfer_timeout" {
		t.Fatalf("upload failure = %+v, want transfer_timeout", failure)
	}

	timedOut = new(atomic.Bool)
	session = newBlockingSession(func() { timedOut.Store(true) })
	got = collectResumeRemoteFirst(session, 20*time.Millisecond, &TransferResult{}, 3, timedOut, &stdout, io.EOF, machinecontract.ResumeRetryFailed)
	if failure := got.ContractFailure(); failure.Error != "transfer_timeout" {
		t.Fatalf("resume failure = %+v, want transfer_timeout", failure)
	}
}
