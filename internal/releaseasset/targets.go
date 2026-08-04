package releaseasset

import "fmt"

// Target is one supported release build platform.
type Target struct {
	GOOS   string
	GOARCH string
}

var supportedTargets = [...]Target{
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
	{GOOS: "darwin", GOARCH: "amd64"},
	{GOOS: "darwin", GOARCH: "arm64"},
	{GOOS: "windows", GOARCH: "amd64"},
	{GOOS: "windows", GOARCH: "arm64"},
}

// SupportedTargets returns the release matrix without exposing mutable package state.
func SupportedTargets() []Target {
	targets := make([]Target, len(supportedTargets))
	copy(targets, supportedTargets[:])
	return targets
}

// Name returns the updater and release artifact name for a platform.
func Name(goos, goarch string) string {
	name := "ssm-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// ProvenanceName returns the adjacent Sigstore bundle name for a release asset.
func ProvenanceName(asset string) string {
	return asset + ".sigstore.json"
}

// ExpectedReleaseNames returns the one accepted release-asset manifest.
func ExpectedReleaseNames() []string {
	names := make([]string, 0, len(supportedTargets)*2+2)
	for _, target := range supportedTargets {
		names = append(names, Name(target.GOOS, target.GOARCH))
	}
	for _, target := range supportedTargets {
		names = append(names, ProvenanceName(Name(target.GOOS, target.GOARCH)))
	}
	names = append(names, "install.sh", "checksums.txt")
	return names
}

// ValidateReleaseNames rejects incomplete, duplicate, misnamed, unsupported,
// or additional release assets.
func ValidateReleaseNames(names []string) error {
	expected := ExpectedReleaseNames()
	if len(names) != len(expected) {
		return fmt.Errorf("release declares %d assets, want exactly %d", len(names), len(expected))
	}
	allowed := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		allowed[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("release asset %q is unsupported or misnamed", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("release asset %q is duplicated", name)
		}
		seen[name] = struct{}{}
	}
	for _, name := range expected {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("release asset %q is missing", name)
		}
	}
	return nil
}
