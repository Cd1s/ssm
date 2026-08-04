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
	for _, forbidden := range []string{"time.Sleep", "time.After"} {
		if strings.Contains(string(source), forbidden) {
			t.Errorf("native Windows suite contains timed polling %q", forbidden)
		}
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

func TestWindowsMappedCleanupUsesDeletePendingHandleEvidence(t *testing.T) {
	source, err := os.ReadFile("replace_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	const start = "func testWindowsMappedExecutableReplacementSucceedsAndCleansOnNextLaunch"
	const end = "func testWindowsPrivilegedReplacement"
	body := string(source)
	startIndex := strings.Index(body, start)
	endIndex := strings.Index(body, end)
	if startIndex < 0 || endIndex <= startIndex {
		t.Fatal("cannot isolate Windows mapped cleanup fixture")
	}
	body = body[startIndex:endIndex]
	for _, required := range []string{
		"openWindowsReplacementFile(backup, 0)",
		"windows.FileStandardInfo",
		"deletePending",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("Windows mapped cleanup fixture lacks handle evidence %q", required)
		}
	}
	cleanupIndex := strings.Index(body, "cleanup := exec.Command")
	if cleanupIndex < 0 {
		t.Fatal("Windows mapped cleanup fixture lacks cleanup child")
	}
	if strings.Contains(body[cleanupIndex:], "os.Stat(backup)") {
		t.Fatal("Windows mapped cleanup fixture races a delete-pending pathname reopen")
	}
}
