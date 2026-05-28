package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		latest  string
		current string
		want    bool
	}{
		{"v1.0.1", "1.0.0", true},
		{"v1.0.0", "1.0.0", false},
		{"1.2.0", "1.1.9", true},
		{"v0.9.9", "1.0.0", false},
	}
	for _, tc := range cases {
		if got := newerVersion(tc.latest, tc.current); got != tc.want {
			t.Fatalf("newerVersion(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

func TestReleaseRepoCanBeDisabledByEnvironment(t *testing.T) {
	for _, value := range []string{"off", "none", "disabled", " OFF "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("SSM_UPDATE_REPO", value)
			if got := releaseRepo(); got != "" {
				t.Fatalf("releaseRepo() = %q, want disabled", got)
			}
		})
	}
}

func TestAutoDisabledDoesNotWriteCooldownFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSM_UPDATE_REPO", "off")

	if err := Auto("1.0.0"); err != nil {
		t.Fatalf("Auto: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "ssm", ".update-available")); !os.IsNotExist(err) {
		t.Fatalf("update flag exists or stat failed unexpectedly: %v", err)
	}
}
