//go:build windows

package machinecontract

import (
	"os"
	"syscall"
	"testing"
)

func TestClassifySSHRecognizesWinsockErrnos(t *testing.T) {
	t.Parallel()
	for _, errno := range []syscall.Errno{10053, 10054} {
		err := os.NewSyscallError("wsarecv", errno)
		got := ClassifySSH(err, SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22})
		if got.Error != CodeConnectionLost {
			t.Fatalf("ClassifySSH(errno %d) = %+v, want connection_lost", errno, got)
		}
	}
}

func TestClassifyTransferCarriedDiagnosisBeatsWinsockErrno(t *testing.T) {
	t.Parallel()
	context := SSHContext{Alias: "prod", Host: "192.0.2.1", Port: 22}
	for _, errno := range []syscall.Errno{10053, 10054} {
		cause := os.NewSyscallError("wsasend", errno)
		carried := Classify(IntegrityToolUnavailable, Details{Cause: cause})
		carrier := &testTransferFailureCarrier{failure: carried, cause: cause}
		if got := ClassifyTransferOperation(carrier, context, carried); got.Error != "integrity_tool_unavailable" || got.Exit != 1 {
			t.Fatalf("put errno %d = %+v", errno, got)
		}
		generic := Classify(TransferRemoteWriteFailed, Details{Cause: cause})
		carrier = &testTransferFailureCarrier{failure: generic, cause: cause}
		if got := ClassifyTransferOperation(carrier, context, generic); got.Error != CodeConnectionLost {
			t.Fatalf("generic put errno %d = %+v", errno, got)
		}
	}
}
