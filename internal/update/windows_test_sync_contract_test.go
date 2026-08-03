package update

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsRenameGapFixtureUsesUntimedProcessSynchronization(t *testing.T) {
	source, err := os.ReadFile("replace_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	const start = "func testWindowsSourceSubstitutionAtRenameGap"
	const end = "func testWindowsCanonicalSubstitutionAtRenameGap"
	body := string(source)
	startIndex := strings.Index(body, start)
	endIndex := strings.Index(body, end)
	if startIndex < 0 || endIndex <= startIndex {
		t.Fatalf("cannot isolate Windows rename-gap fixture")
	}
	body = body[startIndex:endIndex]
	if !strings.Contains(body, "windowsReplacementPipeReady") {
		t.Fatal("Windows rename-gap fixture does not use process-pipe synchronization")
	}
	for _, forbidden := range []string{
		"waitForWindowsTestPath",
		"time.Sleep",
		"time.After",
		"WithTimeout",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("Windows rename-gap fixture retains timed polling %q", forbidden)
		}
	}
}
