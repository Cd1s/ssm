package ssh

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectAndAcceptHostKeyRequiresExactFingerprint(t *testing.T) {
	conn, _ := startRunTestSSHServer(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	inspection, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.OK || inspection.Status != "new" || inspection.Fingerprint == "" || inspection.ObservedFingerprint != inspection.Fingerprint || inspection.Hint == "" {
		t.Fatalf("inspection = %+v", inspection)
	}
	if _, err := AcceptHostKey(conn, "SHA256:not-the-key"); err == nil {
		t.Fatal("accepted the wrong fingerprint")
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "known_hosts")); !os.IsNotExist(err) {
		t.Fatalf("wrong fingerprint changed known_hosts: %v", err)
	}

	accepted, err := AcceptHostKey(conn, inspection.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.Accepted || accepted.Status != "trusted" {
		t.Fatalf("accepted = %+v", accepted)
	}
	trusted, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.Status != "trusted" || trusted.Fingerprint != inspection.Fingerprint {
		t.Fatalf("trusted = %+v", trusted)
	}
}

func TestAcceptHostKeyAtomicallyReplacesMismatch(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is required for mismatch replacement")
	}
	conn, _ := startRunTestSSHServer(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".ssh", "known_hosts")
	if err := saveHostKey(path, knownHostToken(conn), testPublicKey(t)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // test-owned known_hosts path
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "mismatch" {
		t.Fatalf("inspection = %+v", inspection)
	}
	if inspection.ObservedFingerprint == "" || inspection.Hint == "" || !strings.Contains(inspection.Hint, "never remove") {
		t.Fatalf("unsafe mismatch diagnosis: %+v", inspection)
	}
	if _, err := AcceptHostKey(conn, "SHA256:wrong"); err == nil {
		t.Fatal("accepted wrong fingerprint over a mismatch")
	}
	afterWrong, err := os.ReadFile(path) //nolint:gosec // test-owned known_hosts path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, afterWrong) {
		t.Fatal("wrong fingerprint modified known_hosts")
	}
	accepted, err := AcceptHostKey(conn, inspection.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.Accepted || accepted.Status != "trusted" {
		t.Fatalf("accepted = %+v", accepted)
	}
	trusted, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.Status != "trusted" {
		t.Fatalf("trusted = %+v", trusted)
	}
}
