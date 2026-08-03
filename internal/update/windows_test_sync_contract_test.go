package update

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsRenameGapFixtureUsesInProcessHookSynchronization(t *testing.T) {
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
	if !strings.Contains(body, "windowsReplacementTestHook") ||
		!strings.Contains(body, "make(chan struct{})") {
		t.Fatal("Windows rename-gap fixture does not use in-process hook synchronization")
	}
	for _, forbidden := range []string{
		"windowsReplacementTestCommand",
		"StdinPipe",
		"StdoutPipe",
		"ReadString",
		"Process.Kill",
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
