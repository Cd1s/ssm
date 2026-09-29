package ssh

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"ssm/internal/machinecontract"
)

func TestAnnotateLeftoverTempNamesThePath(t *testing.T) {
	base := transferError(machinecontract.TransferTimedOut, 3, errors.New("sftp: connection lost"))
	got := annotateLeftoverTemp(base, "/srv/app.bin.ssm-upload.abc123")
	var transferErr *TransferError
	if !errors.As(got, &transferErr) {
		t.Fatalf("error type = %T", got)
	}
	failure := transferErr.ContractFailure()
	for _, text := range []string{failure.Message, got.Error()} {
		if !strings.Contains(text, "/srv/app.bin.ssm-upload.abc123") || !strings.Contains(text, "may remain") {
			t.Fatalf("leftover path not reported: %q", text)
		}
	}
	if failure.Error != "transfer_timeout" || transferErr.BytesSent != 3 {
		t.Fatalf("failure identity changed: %+v", failure)
	}
	plain := errors.New("not a transfer error")
	if annotateLeftoverTemp(plain, "x") != plain {
		t.Fatal("non-transfer errors must pass through")
	}
}

type stalledRemover struct{ release chan struct{} }

func (r stalledRemover) Remove(string) error { <-r.release; return nil }
func (r stalledRemover) Close() error        { return nil }

func TestRemoveOnFreshSessionIsBounded(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	stalledRemove := removeOnFreshSession(func() (sftpRemover, error) {
		return stalledRemover{release: release}, nil
	}, "/tmp/x.ssm-upload.1", 100*time.Millisecond)
	if stalledRemove || time.Since(start) > 3*time.Second {
		t.Fatalf("stalled remove: removed=%v after %v", stalledRemove, time.Since(start))
	}
	stalledOpen := removeOnFreshSession(func() (sftpRemover, error) {
		<-release
		return nil, errors.New("late")
	}, "/tmp/x.ssm-upload.1", 100*time.Millisecond)
	if stalledOpen {
		t.Fatal("stalled handshake reported as removed")
	}
	ok := removeOnFreshSession(func() (sftpRemover, error) { return okRemover{}, nil }, "/tmp/x", time.Second)
	gone := removeOnFreshSession(func() (sftpRemover, error) { return okRemover{err: os.ErrNotExist}, nil }, "/tmp/x", time.Second)
	if !ok || !gone {
		t.Fatalf("successful cleanup misreported: ok=%v gone=%v", ok, gone)
	}
}

type okRemover struct{ err error }

func (r okRemover) Remove(string) error { return r.err }
func (r okRemover) Close() error        { return nil }
