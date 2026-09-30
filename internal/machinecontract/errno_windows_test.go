//go:build windows

package machinecontract

import (
	"net"
	"os"
	"strings"
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

func TestClassifySSHRecognizesWinsockDialErrnos(t *testing.T) {
	t.Parallel()
	tests := map[syscall.Errno]string{
		10061: CodeDialRefused, 10060: CodeDialTimeout, 10065: CodeDialNetwork, 10051: CodeDialNetwork, 10050: CodeDialNetwork, 10064: CodeDialNetwork,
	}
	for errno, want := range tests {
		// The shape Go returns on Windows: the localized "connectex: ..."
		// text is not matched by any message fallback, only the errno is.
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", errno)}
		got := ClassifySSH(err, SSHContext{Alias: "prod", Host: "127.0.0.1", Port: 22, Stage: "dial"})
		if got.Error != want || got.Stage != "dial" || got.Exit != ExitConnectionFailed {
			t.Fatalf("ClassifySSH(errno %d) = %+v, want %s", errno, got, want)
		}
		// The same Winsock errno on an established session is not a dial.
		session := ClassifySSH(opaqueErrnoError{errno}, SSHContext{Alias: "prod", Host: "127.0.0.1", Port: 22, Stage: "session", ExecPhase: true})
		if strings.HasPrefix(session.Error, "dial_") {
			t.Fatalf("session-stage errno %d classified as %+v", errno, session)
		}
	}
}
