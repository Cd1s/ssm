package ssh

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/machinecontract"
)

func TestValidateUploadDirWalkRejectsEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateUploadDirWalk(dir); err == nil || !strings.Contains(err.Error(), "empty directory") {
		t.Fatalf("expected empty-directory validation error, got %v", err)
	}
}

func TestValidateUploadDirWalkRejectsNonRegularEntry(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("missing-target", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := validateUploadDirWalk(dir); err == nil || !strings.Contains(err.Error(), "non-regular entry") {
		t.Fatalf("expected non-regular validation error, got %v", err)
	}
}

func TestLocalTreeFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0700)
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("b"), 0600)
	files, err := LocalTreeFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files=%v", files)
	}
}

func TestRemoteParentDirStillWorks(t *testing.T) {
	if RemoteParentDir("/a/b/c") != "/a/b" {
		t.Fatal(RemoteParentDir("/a/b/c"))
	}
}

func TestSuperviseDirectoryDownloadLocalFailureReleasesRemote(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	localErr := errors.New("local disk full")
	done := make(chan struct{})
	var remoteErr, gotLocal error
	var first downloadEnd
	go func() {
		defer close(done)
		first, remoteErr, gotLocal = superviseDirectoryDownload(
			func() error { <-release; return errors.New("channel closed") },
			func() error { return localErr },
			func() { once.Do(func() { close(release) }) },
			func() { t.Error("local end must not be killed when it failed first") },
			20*time.Millisecond,
		)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("download supervision hung after the local end failed")
	}
	if first != downloadEndLocal || !errors.Is(gotLocal, localErr) || remoteErr == nil {
		t.Fatalf("first=%v local=%v remote=%v", first, gotLocal, remoteErr)
	}
}

func TestSuperviseDirectoryDownloadRemoteFailureKillsLocal(t *testing.T) {
	kill := make(chan struct{})
	var once sync.Once
	remoteFailure := errors.New("remote tar failed")
	done := make(chan struct{})
	var first downloadEnd
	var gotRemote error
	go func() {
		defer close(done)
		first, gotRemote, _ = superviseDirectoryDownload(
			func() error { return remoteFailure },
			func() error { <-kill; return errors.New("killed") },
			func() { t.Error("remote end must not be closed when it failed first") },
			func() { once.Do(func() { close(kill) }) },
			time.Second,
		)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("download supervision hung after the remote end failed")
	}
	if first != downloadEndRemote || !errors.Is(gotRemote, remoteFailure) {
		t.Fatalf("first=%v remote=%v", first, gotRemote)
	}
}

func TestSuperviseDirectoryDownloadSuccess(t *testing.T) {
	first, remoteErr, localErr := superviseDirectoryDownload(
		func() error { return nil }, func() error { return nil },
		func() { t.Error("unexpected close") }, func() { t.Error("unexpected kill") },
		time.Second,
	)
	if remoteErr != nil || localErr != nil || first != downloadEndNone {
		t.Fatalf("remote=%v local=%v first=%v", remoteErr, localErr, first)
	}
}

func TestRemoteDirCreateCommandModes(t *testing.T) {
	if got := remoteDirCreateCommand("/srv/x y", 0); got != "(umask 022; mkdir -p -- '/srv/x y')" {
		t.Fatalf("default command = %q", got)
	}
	if got := remoteDirCreateCommand("/srv/x", 0o750); got != "(umask 027; mkdir -p -- '/srv/x')" {
		t.Fatalf("dir-mode command = %q", got)
	}
}

func TestRemoteExtractErrorUsesRemoteMessageAndContractStage(t *testing.T) {
	err := remoteExtractError("tar: ./a: Cannot open: Permission denied", errors.New("Process exited with status 2"), "")
	failure, ok := machinecontract.FailureFromError(err)
	if !ok || failure.Stage != "remote_extract" || failure.Error != "remote_write_failed" {
		t.Fatalf("failure = %+v ok=%v", failure, ok)
	}
	if !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("message = %q", err)
	}
}

func TestSuperviseDirectoryDownloadRemoteExitFailureWinsOverLocalEOF(t *testing.T) {
	remoteFailure := &gossh.ExitError{}
	localEOF := errors.New("tar: Unexpected EOF in archive")
	first, remoteErr, localErr := superviseDirectoryDownload(
		func() error { time.Sleep(50 * time.Millisecond); return remoteFailure },
		func() error { return localEOF },
		func() { t.Error("remote must not be closed while it is still reporting its exit status") },
		func() {},
		2*time.Second,
	)
	if first != downloadEndRemote || !errors.Is(remoteErr, remoteFailure) || !errors.Is(localErr, localEOF) {
		t.Fatalf("first=%v remote=%v local=%v; the remote failure must be the root cause", first, remoteErr, localErr)
	}
}

func TestSuperviseDirectoryDownloadNonExitRemoteErrorDoesNotOverrideLocal(t *testing.T) {
	// The local end fails first (disk full); the remote then only sees its
	// channel close. The local failure stays the root cause. The ordering is
	// fixed with a delay so the result does not depend on scheduling.
	first, _, _ := superviseDirectoryDownload(
		func() error { time.Sleep(50 * time.Millisecond); return io.EOF },
		func() error { return errors.New("disk full") },
		func() {}, func() {}, 2*time.Second,
	)
	if first != downloadEndLocal {
		t.Fatalf("first=%v, want local when the remote only saw a closed channel", first)
	}
}

func TestSuperviseDirectoryDownloadRemoteEOFAloneIsARemoteFailure(t *testing.T) {
	first, remoteErr, localErr := superviseDirectoryDownload(
		func() error { return io.EOF },
		func() error { time.Sleep(20 * time.Millisecond); return nil },
		func() {}, func() {}, 2*time.Second,
	)
	if first != downloadEndRemote || !errors.Is(remoteErr, io.EOF) || localErr != nil {
		t.Fatalf("first=%v remote=%v local=%v", first, remoteErr, localErr)
	}
}
