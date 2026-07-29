//go:build !unix && !windows

package inventorytransaction

import (
	"errors"
	"os"
	"testing"
)

func assertPublishingIntentFileClosed(t *testing.T, file *os.File, failure string) {
	t.Helper()
	var probe [1]byte
	if _, err := file.Read(probe[:]); !errors.Is(err, os.ErrClosed) {
		_ = file.Close()
		t.Fatalf("%s: %v", failure, err)
	}
}
