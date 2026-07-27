package releaseasset

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
