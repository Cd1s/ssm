package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ssm/internal/provenance"
	"ssm/internal/provenancefixture"
	"ssm/internal/releaseasset"
)

func TestUnixVerifiedReplacementRejectsCallbackSubstitution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o751); err != nil { //nolint:gosec // make the asserted fixture mode independent of the process umask
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement")
	version := serveAuthenticatedUpdate(t, payload)

	callbackCalled := false
	err := DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		matches, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
		if globErr != nil || len(matches) != 1 {
			return fmt.Errorf("find authenticated stage: matches=%v err=%w", matches, globErr)
		}
		if renameErr := os.Rename(matches[0], matches[0]+".authenticated"); renameErr != nil {
			return fmt.Errorf("move authenticated stage: %w", renameErr)
		}
		if writeErr := os.WriteFile(matches[0], []byte("callback substitute"), 0o751); writeErr != nil { //nolint:gosec // adversarial test-owned replacement
			return fmt.Errorf("write callback substitute: %w", writeErr)
		}
		return nil
	})
	if !callbackCalled {
		t.Fatal("verified replacement did not reach callback")
	}
	if err == nil || !strings.Contains(err.Error(), "authenticated bytes") {
		t.Fatalf("callback substitution error = %v, want authenticated-byte rejection", err)
	}
	assertExecutablePreserved(t, exe, []byte("old"))
}

func TestUnixVerifiedReplacementPreservesOriginalModeAcrossCallbackStagingChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable mode is the authoritative replacement mode
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o751); err != nil { //nolint:gosec // make the asserted fixture mode independent of the process umask
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement with preserved mode")
	version := serveAuthenticatedUpdate(t, payload)

	callbackCalled := false
	err := DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		matches, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
		if globErr != nil || len(matches) != 1 {
			return fmt.Errorf("find authenticated stage: matches=%v err=%w", matches, globErr)
		}
		if chmodErr := os.Chmod(matches[0], 0o777); chmodErr != nil { //nolint:gosec // adversarial test-owned mode mutation is intentional
			return fmt.Errorf("change authenticated staging mode: %w", chmodErr)
		}
		return nil
	})
	if err != nil || !callbackCalled {
		t.Fatalf("verified replacement error=%v callback_called=%t", err, callbackCalled)
	}
	assertExecutablePreserved(t, exe, payload)
}

func TestUnixVerifiedReplacementPreservesExecuteOnlyOriginalMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o700); err != nil { //nolint:gosec // mode is restricted below after fixture creation
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o111); err != nil { //nolint:gosec // test-owned restrictive executable mode is the behavior under test
		t.Skipf("execute-only executable mode is not supported: %v", err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated execute-only replacement")
	version := serveAuthenticatedUpdate(t, payload)

	callbackCalled := false
	err := DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		return nil
	})
	if err != nil || !callbackCalled {
		t.Fatalf("execute-only replacement error=%v callback_called=%t", err, callbackCalled)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o111 {
		t.Fatalf("execute-only replacement mode = %o, want 111", info.Mode().Perm())
	}
	if err := os.Chmod(exe, 0o511); err != nil { //nolint:gosec // test-owned fixture is made readable only for byte verification
		t.Fatalf("make execute-only replacement readable for byte verification: %v", err)
	}
	assertExecutableBytes(t, exe, string(payload))
}

func TestUnixVerifiedReplacementUsesOpenedStageAcrossPathRename(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated opened replacement")
	version := serveAuthenticatedUpdate(t, payload)

	hookCalled := false
	unixReplacementTestHook = func(phase, staged, _ string) error {
		if phase != "source_open" {
			return nil
		}
		hookCalled = true
		if err := os.Rename(staged, staged+".opened"); err != nil {
			return fmt.Errorf("rename opened stage pathname: %w", err)
		}
		if err := os.WriteFile(staged, []byte("concurrent pathname replacement"), 0o751); err != nil { //nolint:gosec // adversarial test-owned replacement
			return fmt.Errorf("replace opened stage pathname: %w", err)
		}
		return nil
	}

	if err := DownloadVersion(version, false); err != nil {
		t.Fatalf("opened-stage replacement failed: %v", err)
	}
	if !hookCalled {
		t.Fatal("opened-stage pathname race did not reach the replacement seam")
	}
	assertExecutableBytes(t, exe, string(payload))
}

func TestUnixVerifiedReplacementRejectsInPlaceCopyMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement before in-place mutation")
	version := serveAuthenticatedUpdate(t, payload)

	hookCalled := false
	unixReplacementTestHook = func(phase, _, install string) error {
		if phase != "copy_ready" {
			return nil
		}
		hookCalled = true
		file, err := os.OpenFile(install, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // adversarial test-owned mutation
		if err != nil {
			return fmt.Errorf("open authenticated copy for mutation: %w", err)
		}
		if _, err := file.Write([]byte("\nin-place mutation\n")); err != nil {
			_ = file.Close()
			return fmt.Errorf("mutate authenticated copy: %w", err)
		}
		return file.Close()
	}

	err := DownloadVersion(version, false)
	if !hookCalled {
		t.Fatal("in-place mutation did not reach the authenticated-copy race seam")
	}
	if err == nil || !strings.Contains(err.Error(), "authenticated bytes") {
		t.Fatalf("in-place copy mutation error = %v, want authenticated-byte rejection", err)
	}
	assertExecutableBytes(t, exe, "old")
}

func TestUnixVerifiedReplacementRejectsAuthenticatedCopyHardLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement before hard link")
	version := serveAuthenticatedUpdate(t, payload)

	hookCalled := false
	unixReplacementTestHook = func(phase, _, install string) error {
		if phase != "copy_ready" {
			return nil
		}
		hookCalled = true
		if err := os.Link(install, install+".alias"); err != nil {
			return fmt.Errorf("create authenticated-copy hard link: %w", err)
		}
		return nil
	}

	err := DownloadVersion(version, false)
	if !hookCalled {
		t.Fatal("hard-link mutation did not reach the authenticated-copy race seam")
	}
	if err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("authenticated-copy hard-link error = %v, want hard-link rejection", err)
	}
	assertExecutableBytes(t, exe, "old")
}

func TestUnixVerifiedReplacementRejectsCommitBoundarySubstitution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o751); err != nil { //nolint:gosec // make the asserted fixture mode independent of the process umask
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement before commit-boundary substitution")
	version := serveAuthenticatedUpdate(t, payload)

	hookCalled := false
	unixReplacementTestHook = func(phase, _, install string) error {
		if phase != "before_commit" {
			return nil
		}
		hookCalled = true
		if err := os.Rename(install, install+".verified"); err != nil {
			return fmt.Errorf("move authenticated install inode: %w", err)
		}
		if err := os.WriteFile(install, []byte("attacker bytes"), 0o751); err != nil { //nolint:gosec // adversarial pathname substitution is intentional
			return fmt.Errorf("substitute unauthenticated install pathname: %w", err)
		}
		return nil
	}

	err := DownloadVersion(version, false)
	if !hookCalled {
		t.Fatal("commit-boundary substitution did not reach the final authenticated seam")
	}
	if err == nil {
		t.Fatal("commit-boundary pathname substitution reported success")
	}
	assertExecutablePreserved(t, exe, []byte("old"))
}

func TestUnixVerifiedReplacementRejectsCallbackObjectMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{
			name: "same path in place",
			mutate: func(stage string) error {
				file, err := os.OpenFile(stage, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // adversarial test-owned mutation
				if err != nil {
					return err
				}
				if _, err := file.Write([]byte("\ncallback mutation\n")); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			},
		},
		{
			name: "through hard link",
			mutate: func(stage string) error {
				alias := stage + ".alias"
				if err := os.Link(stage, alias); err != nil {
					return err
				}
				file, err := os.OpenFile(alias, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // adversarial test-owned mutation
				if err != nil {
					return err
				}
				if _, err := file.Write([]byte("\nhard-link mutation\n")); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			setTestHome(t, t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")

			directory := t.TempDir()
			exe := filepath.Join(directory, "ssm")
			if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
				t.Fatal(err)
			}
			executablePath = func() (string, error) { return exe, nil }
			evalSymlinks = func(path string) (string, error) { return path, nil }

			payload := []byte("authenticated replacement before callback mutation")
			version := serveAuthenticatedUpdate(t, payload)

			err := DownloadVersionBeforeReplace(version, false, func() error {
				matches, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
				if globErr != nil || len(matches) != 1 {
					return fmt.Errorf("find authenticated stage: matches=%v err=%w", matches, globErr)
				}
				return test.mutate(matches[0])
			})
			if err == nil || !strings.Contains(err.Error(), "authenticated bytes") {
				t.Fatalf("callback object mutation error = %v, want authenticated-byte rejection", err)
			}
			assertExecutableBytes(t, exe, "old")
		})
	}
}

func TestVerifiedReplacementPreservesPermissionsAndTarget(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	sentinel := filepath.Join(directory, "sentinel")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of replacement coverage
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil { //nolint:gosec // test-owned sibling proves target scope
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	const version = "v9.9.9"
	payload := []byte("verified replacement")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}

	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	callbackCalled := false
	err = DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		assertExecutableBytes(t, exe, "old")
		return nil
	})
	if err != nil || !callbackCalled {
		t.Fatalf("verified replacement error=%v callback_called=%t", err, callbackCalled)
	}
	assertExecutableBytes(t, exe, string(payload))
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("verified replacement mode = %o, want %o", info.Mode().Perm(), before.Mode().Perm())
	}
	assertExecutableBytes(t, sentinel, "preserve")
}

func serveAuthenticatedUpdate(t *testing.T, payload []byte) string {
	t.Helper()
	const version = "v9.9.9"
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	downloadBaseURL = server.URL
	httpClient = server.Client()
	return version
}

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func assertExecutableBytes(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // callers pass test-owned executable paths
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("executable = %q, want %q", data, want)
	}
}

func assertExecutablePreserved(t *testing.T, path string, want []byte) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // callers pass test-owned executable paths
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) || info.Mode().Perm() != 0o751 {
		t.Fatalf("executable was not preserved: bytes_equal=%t mode=%o want_mode=%o", bytes.Equal(data, want), info.Mode().Perm(), 0o751)
	}
}
