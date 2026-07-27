//go:build unix

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHDExecutableAlternativeSelection(t *testing.T) {
	prerequisite := Prerequisite{
		Kind:    "executable_alternatives",
		Name:    "sshd",
		Version: "SSHD-then-PATH-then-/usr/sbin/sshd",
	}

	t.Run("explicit override", func(t *testing.T) {
		t.Setenv("SSHD", "/bin/true")
		t.Setenv("PATH", "/usr/bin:/bin")
		state := checkPrerequisite(context.Background(), ".", prerequisite, newTestProcessEnvironment(t))
		if !state.available || state.detail != "/bin/true (SSHD override)" {
			t.Fatalf("state = %+v, want selected explicit override", state)
		}

		command := exec.Command("bash", "scripts/ssh_matrix_test.sh", "--select-sshd")
		command.Dir = filepath.Join("..", "..")
		command.Env = []string{"PATH=/usr/bin:/bin", "SSHD=/bin/true"}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("script rejected executable override: %v\n%s", err, output)
		}
		if got, want := strings.TrimSpace(string(output)), "/bin/true"; got != want {
			t.Fatalf("selected SSHD = %q, want %q", got, want)
		}
	})

	t.Run("invalid explicit override does not fall back", func(t *testing.T) {
		t.Setenv("SSHD", filepath.Join(t.TempDir(), "missing-sshd"))
		t.Setenv("PATH", "/usr/sbin:/usr/bin:/bin")
		state := checkPrerequisite(context.Background(), ".", prerequisite, newTestProcessEnvironment(t))
		if state.available || !strings.Contains(state.detail, "invalid SSHD override") {
			t.Fatalf("state = %+v, want clear invalid-override failure", state)
		}

		command := exec.Command("bash", "scripts/ssh_matrix_test.sh", "--select-sshd")
		command.Dir = filepath.Join("..", "..")
		command.Env = []string{
			"PATH=/usr/sbin:/usr/bin:/bin",
			"SSHD=" + filepath.Join(t.TempDir(), "missing-sshd"),
		}
		output, err := command.CombinedOutput()
		if err == nil {
			t.Fatalf("script accepted invalid explicit override: %s", output)
		}
		if !strings.Contains(string(output), "invalid SSHD override") {
			t.Fatalf("script failure was not explicit:\n%s", output)
		}
	})

	t.Run("PATH candidate", func(t *testing.T) {
		bin := t.TempDir()
		candidate := filepath.Join(bin, "sshd")
		if err := os.Symlink("/bin/true", candidate); err != nil {
			t.Fatalf("create PATH sshd fixture: %v", err)
		}
		t.Setenv("SSHD", "")
		if err := os.Unsetenv("SSHD"); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin)
		state := checkPrerequisite(context.Background(), ".", prerequisite, newTestProcessEnvironment(t))
		if !state.available || state.detail != candidate+" (PATH)" {
			t.Fatalf("state = %+v, want selected PATH candidate", state)
		}
	})

	t.Run("/usr/sbin fallback", func(t *testing.T) {
		if err := validateExecutableRegularFile("/usr/sbin/sshd"); err != nil {
			t.Skipf("fixed SSHD fallback is unavailable on this host: %v", err)
		}
		bash, err := exec.LookPath("bash")
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("SSHD", "")
		if err := os.Unsetenv("SSHD"); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", t.TempDir())
		state := checkPrerequisite(context.Background(), ".", prerequisite, newTestProcessEnvironment(t))
		if !state.available || state.detail != "/usr/sbin/sshd (/usr/sbin fallback)" {
			t.Fatalf("state = %+v, want selected /usr/sbin fallback", state)
		}

		command := exec.Command(bash, "scripts/ssh_matrix_test.sh", "--select-sshd") //nolint:gosec // bash is resolved from the test process PATH and argv is fixed
		command.Dir = filepath.Join("..", "..")
		command.Env = []string{"PATH=" + t.TempDir()}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("script rejected /usr/sbin fallback: %v\n%s", err, output)
		}
		if got, want := strings.TrimSpace(string(output)), "/usr/sbin/sshd"; got != want {
			t.Fatalf("selected SSHD = %q, want %q", got, want)
		}
	})
}
