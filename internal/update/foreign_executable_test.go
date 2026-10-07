package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installLoaderLayout builds what an Alpine host with gcompat looks like to a
// glibc program: the operating system's C library is what os.Executable
// reports, while the installed ssm is only reachable through argv[0] and PATH.
func installLoaderLayout(t *testing.T) (loader, installed string) {
	t.Helper()
	root := t.TempDir()
	lib := filepath.Join(root, "lib")
	bin := filepath.Join(root, "usr", "local", "bin")
	for _, dir := range []string{lib, bin} {
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // test-owned directories
			t.Fatal(err)
		}
	}
	loader = filepath.Join(lib, "ld-musl-x86_64.so.1")
	installed = filepath.Join(bin, "ssm")
	for path, content := range map[string]string{loader: "operating system library", installed: "old ssm"} {
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil { //nolint:gosec // test-owned executables
			t.Fatal(err)
		}
	}
	return loader, installed
}

func TestResolveInstalledExecutableRefusesLoaderWithoutSSMName(t *testing.T) {
	restoreUpdateTestHooks(t)
	loader, _ := installLoaderLayout(t)
	executablePath = func() (string, error) { return loader, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	commandLineName = func() string { return "/usr/bin/some-other-tool" }

	got, err := resolveInstalledExecutable()
	if err == nil || !strings.Contains(err.Error(), "refusing to update") {
		t.Fatalf("resolve = %q, %v; want a refusal", got, err)
	}
	assertExecutableBytes(t, loader, "operating system library")
}

func TestResolveInstalledExecutableRecoversSSMThroughCommandLine(t *testing.T) {
	restoreUpdateTestHooks(t)
	loader, installed := installLoaderLayout(t)
	executablePath = func() (string, error) { return loader, nil }
	evalSymlinks = filepath.EvalSymlinks
	commandLineName = func() string { return "ssm" }
	lookPath = func(name string) (string, error) {
		if name != "ssm" {
			t.Fatalf("looked up %q, want ssm", name)
		}
		return installed, nil
	}

	got, err := resolveInstalledExecutable()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, _ := filepath.EvalSymlinks(installed)
	if got != want {
		t.Fatalf("resolved %q, want the installed ssm %q (never the loader)", got, want)
	}
}

func TestResolveInstalledExecutableRecoversSshctlSymlink(t *testing.T) {
	restoreUpdateTestHooks(t)
	loader, installed := installLoaderLayout(t)
	link := filepath.Join(filepath.Dir(installed), "sshctl")
	if err := os.Symlink("ssm", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	executablePath = func() (string, error) { return loader, nil }
	evalSymlinks = filepath.EvalSymlinks
	commandLineName = func() string { return "sshctl" }
	lookPath = func(string) (string, error) { return link, nil }

	got, err := resolveInstalledExecutable()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, _ := filepath.EvalSymlinks(installed)
	if got != want {
		t.Fatalf("resolved %q, want %q", got, want)
	}
}

func TestResolveInstalledExecutableRefusesWhenCommandLineResolvesToLoader(t *testing.T) {
	restoreUpdateTestHooks(t)
	loader, _ := installLoaderLayout(t)
	executablePath = func() (string, error) { return loader, nil }
	evalSymlinks = filepath.EvalSymlinks
	commandLineName = func() string { return "ssm" }
	// An "ssm" that is really a link to the library must not be accepted.
	trap := filepath.Join(t.TempDir(), "ssm")
	if err := os.Symlink(loader, trap); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	lookPath = func(string) (string, error) { return trap, nil }

	if got, err := resolveInstalledExecutable(); err == nil {
		t.Fatalf("resolve = %q, want a refusal because the target is the library", got)
	}
	assertExecutableBytes(t, loader, "operating system library")
}

func TestResolveInstalledExecutableKeepsOrdinaryInstall(t *testing.T) {
	restoreUpdateTestHooks(t)
	_, installed := installLoaderLayout(t)
	executablePath = func() (string, error) { return installed, nil }
	evalSymlinks = filepath.EvalSymlinks
	commandLineName = func() string { return "/does/not/matter/and/is/ignored" }
	lookPath = func(string) (string, error) { t.Fatal("LookPath used for an ordinary install"); return "", nil }

	got, err := resolveInstalledExecutable()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, _ := filepath.EvalSymlinks(installed)
	if got != want {
		t.Fatalf("resolved %q, want %q", got, want)
	}
}

func TestResolveInstalledExecutableRejectsOtherCommandNames(t *testing.T) {
	restoreUpdateTestHooks(t)
	loader, installed := installLoaderLayout(t)
	executablePath = func() (string, error) { return loader, nil }
	evalSymlinks = filepath.EvalSymlinks
	// The command line names some other tool, even though PATH lookup would
	// find a file that happens to be called ssm. The name on the command line
	// is what proves this process is ssm, so this must not be accepted.
	commandLineName = func() string { return "backup-helper" }
	lookPath = func(string) (string, error) { return installed, nil }

	if got, err := resolveInstalledExecutable(); err == nil {
		t.Fatalf("resolve = %q, want a refusal for a process not started as ssm or sshctl", got)
	}
}
