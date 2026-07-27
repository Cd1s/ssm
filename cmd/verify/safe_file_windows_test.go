//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsNoFollowReadsNormalFileAndReleasesHandle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "normal.txt")
	writeTestFile(t, path, "normal\n")

	for range 32 {
		data, err := readRegularFileNoFollow(root, "normal.txt")
		if err != nil {
			t.Fatalf("read normal file without following reparse points: %v", err)
		}
		if got, want := string(data), "normal\n"; got != want {
			t.Fatalf("normal file content = %q, want %q", got, want)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("normal file handle leaked across cleanup: %v", err)
	}
}

func TestWindowsNoFollowRejectsLeafReparsePointAndReleasesHandle(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external.txt")
	writeTestFile(t, external, "credential-canary\n")
	link := filepath.Join(root, "leaf-link")
	if err := os.Symlink(external, link); err != nil {
		t.Fatalf("create Windows leaf symlink fixture: %v", err)
	}

	data, err := readRegularFileNoFollow(root, "leaf-link")
	if err == nil {
		t.Fatalf("leaf reparse point was followed, data=%q", data)
	}
	if strings.Contains(err.Error(), "credential-canary") {
		t.Fatalf("leaf-reparse rejection exposed external content: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatalf("leaf reparse handle leaked across cleanup: %v", err)
	}
}

func TestWindowsNoFollowRejectsParentDirectoryReparsePoint(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	writeTestFile(t, filepath.Join(external, "secret.txt"), "credential-canary\n")
	parentLink := filepath.Join(root, "parent-link")
	if err := os.Symlink(external, parentLink); err != nil {
		t.Fatalf("create Windows parent directory reparse fixture: %v", err)
	}

	data, err := readRegularFileNoFollow(root, "parent-link/secret.txt")
	if err == nil {
		t.Fatalf("parent directory reparse point was followed, data=%q", data)
	}
	if strings.Contains(err.Error(), "credential-canary") {
		t.Fatalf("parent-reparse rejection exposed external content: %v", err)
	}
	if err := os.Remove(parentLink); err != nil {
		t.Fatalf("parent reparse handle leaked across cleanup: %v", err)
	}
}

func TestWindowsNoFollowRejectsNonRegularLeaf(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := readRegularFileNoFollow(root, "directory"); err == nil {
		t.Fatal("directory leaf was accepted as a regular file")
	}
	if err := os.Remove(filepath.Join(root, "directory")); err != nil {
		t.Fatalf("nonregular-leaf handle leaked across cleanup: %v", err)
	}
}
