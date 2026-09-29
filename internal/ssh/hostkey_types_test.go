package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func newTestSigner(t *testing.T, kind string) gossh.Signer {
	t.Helper()
	var private any
	switch kind {
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private = key
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private = key
	case "ecdsa384":
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private = key
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		private = key
	default:
		t.Fatalf("unknown test signer kind %q", kind)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func knownLine(host string, signer gossh.Signer) string {
	return knownhosts.Line([]string{host}, signer.PublicKey())
}

func writeTestKnownHosts(t *testing.T, home string, lines ...string) string {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	content := ""
	for _, line := range lines {
		content += line + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func failureCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	failure, ok := machinecontract.FailureFromError(err)
	if !ok {
		t.Fatalf("error is not classified: %v", err)
	}
	return failure.Error
}

func dialAndClose(t *testing.T, conn config.Connection, vault *config.Vault) error {
	t.Helper()
	client, err := dialSSHFresh(conn, vault)
	if err == nil {
		_ = client.Close()
	}
	return err
}

func TestDialPrefersKnownHostKeyTypeOverServerDefaultOrder(t *testing.T) {
	ecdsaSigner, edSigner := newTestSigner(t, "ecdsa"), newTestSigner(t, "ed25519")
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, ecdsaSigner, edSigner)
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home, knownLine(knownHostToken(conn), edSigner))

	if err := dialAndClose(t, conn, vault); err != nil {
		t.Fatalf("known ed25519 key must be accepted although ECDSA is offered too: %v", err)
	}
}

func TestDialSameTypeKeyChangeRemainsMismatch(t *testing.T) {
	ecdsaSigner, edSigner := newTestSigner(t, "ecdsa"), newTestSigner(t, "ed25519")
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, ecdsaSigner, edSigner)
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home, knownLine(knownHostToken(conn), newTestSigner(t, "ed25519")))

	if got := failureCode(t, dialAndClose(t, conn, vault)); got != "host_key_mismatch" {
		t.Fatalf("error = %q, want host_key_mismatch", got)
	}
}

func TestDialOnlyKeyTypeDifferenceReportsTypeChanged(t *testing.T) {
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, newTestSigner(t, "ed25519"))
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home, knownLine(knownHostToken(conn), newTestSigner(t, "ecdsa")))

	err := dialAndClose(t, conn, vault)
	if got := failureCode(t, err); got != "host_key_type_changed" {
		t.Fatalf("error = %q, want host_key_type_changed", got)
	}
	failure, _ := machinecontract.FailureFromError(err)
	if failure.Exit != 255 || failure.Stage != "dial" || failure.Hint == "" {
		t.Fatalf("failure policy = %+v", failure)
	}
}

func TestDialWithoutKnownEntryStillRejectsUnknownHost(t *testing.T) {
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, newTestSigner(t, "ecdsa"), newTestSigner(t, "ed25519"))
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home, knownLine("other.example", newTestSigner(t, "ed25519")))

	if got := failureCode(t, dialAndClose(t, conn, vault)); got != "host_key_unknown" {
		t.Fatalf("error = %q, want host_key_unknown", got)
	}
}

func TestInspectHostKeyPrefersKnownTypeAndReportsTrusted(t *testing.T) {
	ecdsaSigner, edSigner := newTestSigner(t, "ecdsa"), newTestSigner(t, "ed25519")
	conn, _, _ := startRunTestSSHServerWithHostKeys(t, ecdsaSigner, edSigner)
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home, knownLine(knownHostToken(conn), edSigner))

	inspection, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "trusted" || inspection.Algorithm != gossh.KeyAlgoED25519 ||
		inspection.Fingerprint != gossh.FingerprintSHA256(edSigner.PublicKey()) {
		t.Fatalf("inspection = %+v", inspection)
	}
}

func TestInspectHostKeyDistinguishesTypeChangeFromMismatch(t *testing.T) {
	edSigner := newTestSigner(t, "ed25519")
	conn, _, _ := startRunTestSSHServerWithHostKeys(t, edSigner)
	home := t.TempDir()
	setTestHome(t, home)
	knownEC := newTestSigner(t, "ecdsa")
	writeTestKnownHosts(t, home, knownLine(knownHostToken(conn), knownEC))

	inspection, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.OK || inspection.Status != "type_changed" || inspection.Classification != "type_changed" ||
		inspection.ObservedFingerprint != gossh.FingerprintSHA256(edSigner.PublicKey()) ||
		len(inspection.KnownFingerprints) != 1 || inspection.KnownFingerprints[0] != gossh.FingerprintSHA256(knownEC.PublicKey()) ||
		!strings.Contains(inspection.Hint, "out-of-band") {
		t.Fatalf("inspection = %+v", inspection)
	}

	writeTestKnownHosts(t, home, knownLine(knownHostToken(conn), newTestSigner(t, "ed25519")))
	inspection, err = InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "mismatch" {
		t.Fatalf("same-type change status = %q, want mismatch", inspection.Status)
	}
}

func TestAcceptReplacesOnlySameTypeEntriesForThisHost(t *testing.T) {
	edSigner := newTestSigner(t, "ed25519")
	conn, _, _ := startRunTestSSHServerWithHostKeys(t, edSigner)
	home := t.TempDir()
	setTestHome(t, home)
	token := knownHostToken(conn)

	otherEd := newTestSigner(t, "ed25519")
	keepECDSA := newTestSigner(t, "ecdsa")
	oldPlain, oldHashed, oldShared := newTestSigner(t, "ed25519"), newTestSigner(t, "ed25519"), newTestSigner(t, "ed25519")
	authority, revoked := newTestSigner(t, "ed25519"), newTestSigner(t, "ed25519")
	otherPortSameHost := newTestSigner(t, "ed25519")

	keptPrefix := []string{
		"# maintained by hand",
		knownLine("other.example", otherEd),
		knownLine(token, keepECDSA),
		"",
		"@cert-authority " + knownLine(token, authority),
		"@revoked " + knownLine("*", revoked),
		knownLine("[127.0.0.1]:1", otherPortSameHost),
	}
	original := strings.Join(append(append([]string{}, keptPrefix...),
		knownLine(token, oldPlain),
		knownLine(knownhosts.HashHostname(token), oldHashed),
		knownhosts.Line([]string{"shared.example", token}, oldShared.PublicKey()),
	), "\n") + "\n"
	path := filepath.Join(home, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil { //nolint:gosec // test needs a non-0600 mode to prove it is preserved
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // test needs a non-0600 mode to prove it is preserved
		t.Fatal(err)
	}

	inspection, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "mismatch" {
		t.Fatalf("inspection = %+v", inspection)
	}
	if _, err := AcceptHostKey(conn, inspection.ObservedFingerprint); err != nil {
		t.Fatal(err)
	}

	want := strings.Join(keptPrefix, "\n") + "\n" +
		knownLine("shared.example", oldShared) + "\n" +
		knownLine(token, edSigner) + "\n"
	got, err := os.ReadFile(path) //nolint:gosec // test-owned known_hosts path
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("known_hosts after accept:\n%s\nwant:\n%s", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("known_hosts mode = %v, want 0640 preserved", info.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("leftover files beside known_hosts: %v", entries)
	}
	trusted, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.Status != "trusted" {
		t.Fatalf("after accept = %+v", trusted)
	}
}

func TestAcceptTypeChangeKeepsExistingOtherTypeEntry(t *testing.T) {
	edSigner := newTestSigner(t, "ed25519")
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, edSigner)
	home := t.TempDir()
	setTestHome(t, home)
	knownEC := newTestSigner(t, "ecdsa")
	path := writeTestKnownHosts(t, home, knownLine(knownHostToken(conn), knownEC))
	before, _ := os.ReadFile(path) //nolint:gosec // test-owned known_hosts path

	inspection, err := InspectHostKey(conn)
	if err != nil || inspection.Status != "type_changed" {
		t.Fatalf("inspection = %+v, err = %v", inspection, err)
	}
	if got := failureCode(t, dialAndClose(t, conn, vault)); got != "host_key_type_changed" {
		t.Fatalf("normal operation error = %q", got)
	}
	if _, err := AcceptHostKey(conn, inspection.ObservedFingerprint); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path) //nolint:gosec // test-owned known_hosts path
	if want := string(before) + knownLine(knownHostToken(conn), edSigner) + "\n"; string(after) != want {
		t.Fatalf("known_hosts = %q, want %q", after, want)
	}
	if err := dialAndClose(t, conn, vault); err != nil {
		t.Fatalf("dial after accept: %v", err)
	}
}

func TestReplaceKnownHostAddsNewlineBeforeAppendingToUnterminatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	other := knownLine("other.example", newTestSigner(t, "ed25519"))
	if err := os.WriteFile(path, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := newTestSigner(t, "ed25519")
	if err := replaceKnownHost(path, "host.example", fresh.PublicKey()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path) //nolint:gosec // test-owned known_hosts path
	if want := other + "\n" + knownLine("host.example", fresh) + "\n"; string(got) != want {
		t.Fatalf("known_hosts = %q, want %q", got, want)
	}
}

func TestHostKeyAlgorithmsForOrdersKnownTypesFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	const address = "192.0.2.10:2222"
	token := knownhosts.Normalize(address)
	write := func(lines ...string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Remove(path)
	if got := hostKeyAlgorithmsFor(path, address); got != nil {
		t.Fatalf("missing file: %v", got)
	}
	write(knownLine("other.example", newTestSigner(t, "ed25519")))
	if got := hostKeyAlgorithmsFor(path, address); got != nil {
		t.Fatalf("unrelated host: %v", got)
	}

	assertOrder := func(got []string, first ...string) {
		t.Helper()
		if len(got) < len(first) {
			t.Fatalf("algorithms = %v", got)
		}
		for i, want := range first {
			if got[i] != want {
				t.Fatalf("algorithms[%d] = %q, want %q; all=%v", i, got[i], want, got)
			}
		}
		seen := map[string]bool{}
		for _, algorithm := range got {
			if seen[algorithm] {
				t.Fatalf("duplicate algorithm %q in %v", algorithm, got)
			}
			seen[algorithm] = true
		}
		for _, algorithm := range []string{gossh.KeyAlgoED25519, gossh.KeyAlgoECDSA256, gossh.KeyAlgoRSASHA256} {
			if !seen[algorithm] {
				t.Fatalf("default algorithm %q dropped from %v", algorithm, got)
			}
		}
	}

	write(knownLine(token, newTestSigner(t, "ed25519")))
	assertOrder(hostKeyAlgorithmsFor(path, address), gossh.KeyAlgoED25519)

	write(
		knownLine(token, newTestSigner(t, "rsa")),
		knownLine(knownhosts.HashHostname(token), newTestSigner(t, "ecdsa384")),
	)
	assertOrder(hostKeyAlgorithmsFor(path, address),
		gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSA, gossh.KeyAlgoECDSA384)
}

// newTestHostCertSigner returns a host-certificate signer for hostSigner's key,
// signed by ca.
func newTestHostCertSigner(t *testing.T, hostSigner, ca gossh.Signer) gossh.Signer {
	t.Helper()
	cert := &gossh.Certificate{
		Key:         hostSigner.PublicKey(),
		Serial:      1,
		CertType:    gossh.HostCert,
		ValidBefore: gossh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certSigner, err := gossh.NewCertSigner(cert, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	return certSigner
}

func TestDialSucceedsWithCertAuthorityOnlyKnownHosts(t *testing.T) {
	host, ca := newTestSigner(t, "ed25519"), newTestSigner(t, "ed25519")
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, host, newTestHostCertSigner(t, host, ca))
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home, "@cert-authority "+knownLine(knownHostToken(conn), ca))

	if err := dialAndClose(t, conn, vault); err != nil {
		t.Fatalf("host certificate signed by the known CA must be accepted: %v", err)
	}
}

func TestDialSucceedsWithCertAuthorityAndPlainEntryOfAnotherType(t *testing.T) {
	host, ca := newTestSigner(t, "ed25519"), newTestSigner(t, "ed25519")
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, host, newTestHostCertSigner(t, host, ca))
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home,
		knownLine(knownHostToken(conn), newTestSigner(t, "ecdsa")),
		"@cert-authority "+knownLine(knownHostToken(conn), ca),
	)

	if err := dialAndClose(t, conn, vault); err != nil {
		t.Fatalf("CA entry must keep the certificate-first default order: %v", err)
	}
}

func TestCertAuthorityEntriesDoNotCountAsRecordedHostKeyTypes(t *testing.T) {
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, newTestSigner(t, "ed25519"))
	home := t.TempDir()
	setTestHome(t, home)
	writeTestKnownHosts(t, home, "@cert-authority "+knownLine(knownHostToken(conn), newTestSigner(t, "ecdsa")))

	if got := failureCode(t, dialAndClose(t, conn, vault)); got != "host_key_mismatch" {
		t.Fatalf("plain key against a CA-only entry = %q, want the legacy host_key_mismatch", got)
	}
	inspection, err := InspectHostKey(conn)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "mismatch" {
		t.Fatalf("inspect status = %q, want mismatch", inspection.Status)
	}
}

func TestSaveHostKeyTerminatesUnterminatedLastLine(t *testing.T) {
	edSigner := newTestSigner(t, "ed25519")
	conn, vault, _ := startRunTestSSHServerWithHostKeys(t, edSigner)
	home := t.TempDir()
	setTestHome(t, home)
	path := writeTestKnownHosts(t, home)
	known := knownLine(knownHostToken(conn), newTestSigner(t, "ecdsa"))
	if err := os.WriteFile(path, []byte(known), 0o600); err != nil {
		t.Fatal(err)
	}

	inspection, err := InspectHostKey(conn)
	if err != nil || inspection.Status != "type_changed" {
		t.Fatalf("inspection = %+v, err = %v", inspection, err)
	}
	if _, err := AcceptHostKey(conn, inspection.ObservedFingerprint); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path) //nolint:gosec // test-owned known_hosts path
	if want := known + "\n" + knownLine(knownHostToken(conn), edSigner) + "\n"; string(got) != want {
		t.Fatalf("known_hosts = %q, want %q", got, want)
	}
	if err := dialAndClose(t, conn, vault); err != nil {
		t.Fatalf("dial after accept: %v", err)
	}
}

func TestKnownHostPatternMatchingIsCaseSensitiveLikeKnownHosts(t *testing.T) {
	if knownHostPatternIs("Host.Example", "host.example") {
		t.Fatal("pattern matched with different case; x/crypto knownhosts is case-sensitive")
	}
	if !knownHostPatternIs("host.example", "host.example") {
		t.Fatal("identical pattern did not match")
	}
}
