package releaseasset

import (
	"reflect"
	"testing"
)

func TestSixTargetReleaseManifest(t *testing.T) {
	wantTargets := []Target{
		{GOOS: "linux", GOARCH: "amd64"},
		{GOOS: "linux", GOARCH: "arm64"},
		{GOOS: "darwin", GOARCH: "amd64"},
		{GOOS: "darwin", GOARCH: "arm64"},
		{GOOS: "windows", GOARCH: "amd64"},
		{GOOS: "windows", GOARCH: "arm64"},
	}
	if got := SupportedTargets(); !reflect.DeepEqual(got, wantTargets) {
		t.Fatalf("targets = %#v, want %#v", got, wantTargets)
	}
	names := ExpectedReleaseNames()
	if len(names) != 14 {
		t.Fatalf("release manifest has %d names, want 14: %q", len(names), names)
	}
	if err := ValidateReleaseNames(names); err != nil {
		t.Fatalf("exact manifest rejected: %v", err)
	}
}

func TestReleaseManifestRejectsMissingDuplicateExtraAndMalformedNames(t *testing.T) {
	valid := ExpectedReleaseNames()
	for _, test := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{name: "missing", mutate: func(names []string) []string { return names[1:] }},
		{name: "duplicate", mutate: func(names []string) []string { return append(names, names[0]) }},
		{name: "extra", mutate: func(names []string) []string { return append(names, "ssm-freebsd-amd64") }},
		{name: "malformed", mutate: func(names []string) []string { names[0] += ".zip"; return names }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateReleaseNames(test.mutate(append([]string(nil), valid...))); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}
