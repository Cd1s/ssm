package ssh

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/machinecontract"
)

func TestRegularDownloadFilesystemFailuresPreserveDestinationAndRemoveTemps(t *testing.T) {
	tests := []struct {
		name      string
		wantStage string
		fail      func(*fileDownloadPublishOperations, error)
	}{
		{
			name:      "local write",
			wantStage: "local_write",
			fail: func(operations *fileDownloadPublishOperations, failure error) {
				operations.chmod = func(string, os.FileMode) error { return failure }
			},
		},
		{
			name:      "publish",
			wantStage: "publish",
			fail: func(operations *fileDownloadPublishOperations, failure error) {
				operations.rename = func(string, string) error { return failure }
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "artifact")
			const original = "existing final bytes\n"
			if err := os.WriteFile(destination, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}

			staging, err := newFileDownloadStaging(destination)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := staging.file.WriteString("incomplete replacement bytes\n"); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected " + test.name + " failure")
			operations := systemFileDownloadPublishOperations()
			test.fail(&operations, injected)

			_, err = staging.publish(destination, operations)
			staging.cleanup()
			if !errors.Is(err, injected) {
				t.Fatalf("publish error = %v, want injected failure", err)
			}
			assertDownloadFailureStage(t, err, test.wantStage)
			assertFileContents(t, destination, original)
			assertNoDownloadTemporaryOutputs(t, parent)
		})
	}
}

func TestDirectoryDownloadPublishFailureRestoresDestinationAndRemovesTemps(t *testing.T) {
	parent := t.TempDir()
	destination := filepath.Join(parent, "tree")
	writePreservedDirectoryFixture(t, destination)

	staging, err := newDirectoryDownloadStaging(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging.path, "existing.txt"), []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging.path, "new.txt"), []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected directory publish failure")
	operations := systemDirectoryDownloadPublishOperations()
	renameCalls := 0
	operations.rename = func(oldPath, newPath string) error {
		renameCalls++
		if renameCalls == 2 {
			return injected
		}
		return os.Rename(oldPath, newPath)
	}

	err = staging.publish(destination, operations)
	staging.cleanup()
	if !errors.Is(err, injected) {
		t.Fatalf("publish error = %v, want injected failure", err)
	}
	assertDownloadFailureStage(t, err, "publish")
	assertPreservedDirectoryFixture(t, destination)
	assertNoDownloadTemporaryOutputs(t, parent)
}

func TestDirectoryDownloadRestoreFailureRetainsBackupWithoutPreservationClaim(t *testing.T) {
	parent := t.TempDir()
	destination := filepath.Join(parent, "tree")
	writePreservedDirectoryFixture(t, destination)

	staging, err := newDirectoryDownloadStaging(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging.path, "existing.txt"), []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	publishFailure := errors.New("injected directory publish failure")
	restoreFailure := errors.New("injected directory restore failure")
	operations := systemDirectoryDownloadPublishOperations()
	renameCalls := 0
	operations.rename = func(oldPath, newPath string) error {
		renameCalls++
		switch renameCalls {
		case 2:
			return publishFailure
		case 3:
			return restoreFailure
		default:
			return os.Rename(oldPath, newPath)
		}
	}

	err = staging.publish(destination, operations)
	staging.cleanup()
	if !errors.Is(err, publishFailure) || !errors.Is(err, restoreFailure) {
		t.Fatalf("publish/restore error = %v, want both injected failures", err)
	}
	failure := assertDownloadFailureStage(t, err, "publish")
	for _, falseClaim := range []string{"not replaced", "preserved", "unchanged"} {
		if strings.Contains(strings.ToLower(failure.Hint), falseClaim) {
			t.Fatalf("restore-failure hint falsely claims preservation: %q", failure.Hint)
		}
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("double-failure destination state = %v, want absent after failed restore", statErr)
	}
	stagingOutputs, globErr := filepath.Glob(filepath.Join(parent, ".ssm-get-dir-*"))
	if globErr != nil || len(stagingOutputs) != 0 {
		t.Fatalf("directory staging outputs = %v, error = %v", stagingOutputs, globErr)
	}
	backups, globErr := filepath.Glob(filepath.Join(parent, ".ssm-get-backup-*"))
	if globErr != nil || len(backups) != 1 {
		t.Fatalf("retained backups = %v, error = %v, want exactly one", backups, globErr)
	}
	if !strings.Contains(err.Error(), backups[0]) {
		t.Fatalf("restore error does not name retained backup %q: %v", backups[0], err)
	}
	assertPreservedDirectoryFixture(t, backups[0])
}

func assertDownloadFailureStage(t *testing.T, err error, wantStage string) machinecontract.Failure {
	t.Helper()
	failure, ok := machinecontract.FailureFromError(err)
	if !ok {
		t.Fatalf("download error has no canonical failure: %v", err)
	}
	if failure.Stage != wantStage {
		t.Fatalf("download failure stage = %q, want %q: %+v", failure.Stage, wantStage, failure)
	}
	return failure
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is always beneath the test-owned t.TempDir
	if err != nil || string(data) != want {
		t.Fatalf("file %q contents = %q, error = %v, want %q", path, data, err, want)
	}
}

func assertNoDownloadTemporaryOutputs(t *testing.T, parent string) {
	t.Helper()
	outputs, err := filepath.Glob(filepath.Join(parent, ".ssm-get-*"))
	if err != nil || len(outputs) != 0 {
		t.Fatalf("download temporary outputs = %v, error = %v", outputs, err)
	}
}

func writePreservedDirectoryFixture(t *testing.T, destination string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(destination, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "existing.txt"), []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "nested", "keep.txt"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPreservedDirectoryFixture(t *testing.T, destination string) {
	t.Helper()
	assertFileContents(t, filepath.Join(destination, "existing.txt"), "existing\n")
	assertFileContents(t, filepath.Join(destination, "nested", "keep.txt"), "keep\n")
	if _, err := os.Stat(filepath.Join(destination, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("failed directory download left replacement-only output: %v", err)
	}
}
