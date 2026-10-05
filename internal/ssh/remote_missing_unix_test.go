//go:build unix

package ssh

import (
	"testing"

	"ssm/internal/machinecontract"
)

func TestRemoteMissingDirectoryUsesDownloadRemoteReadClassification(t *testing.T) {
	connection, vault := startRunTestSSHServer(t)
	setTestHome(t, t.TempDir())
	trustRunTestHost(t, connection)
	client, err := dialSSH(connection, vault)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseClient(client, false)
	isDir, err := remoteIsDirOn(client, "/path/that/does/not/exist")
	if isDir {
		t.Fatal("missing remote path reported as a directory")
	}
	if err == nil {
		t.Fatal("missing remote path unexpectedly succeeded")
	}
	failure, ok := machinecontract.FailureFromError(err)
	if !ok {
		t.Fatalf("missing remote path has no canonical failure: %v", err)
	}
	if failure.Error != "remote_read_failed" {
		t.Fatalf("missing remote path error = %q, want remote_read_failed", failure.Error)
	}
}
