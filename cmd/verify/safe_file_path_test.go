package main

import (
	"strings"
	"testing"
)

func TestValidatedRelativePathRejectsBackslashSeparators(t *testing.T) {
	for _, path := range []string{
		`..\outside`,
		`safe\..\outside`,
		`safe\file`,
	} {
		t.Run(path, func(t *testing.T) {
			_, err := validatedRelativePath(path)
			if err == nil || !strings.Contains(err.Error(), "backslash") {
				t.Fatalf("validatedRelativePath(%q) error = %v, want backslash rejection", path, err)
			}
		})
	}
}
