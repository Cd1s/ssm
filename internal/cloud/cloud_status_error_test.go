package cloud

import (
	"strings"
	"testing"
	"unicode"
)

func TestHTTPStatusErrorStripsControlCharacters(t *testing.T) {
	message := "before\x1b]0;title\x07 after\x9b31m done"
	got := (&HTTPStatusError{StatusCode: 500, Message: message}).Error()
	for _, r := range got {
		if unicode.IsControl(r) {
			t.Fatalf("error contains control character U+%04X: %q", r, got)
		}
	}
	if strings.Contains(got, "  ") {
		t.Fatalf("error contains consecutive spaces: %q", got)
	}
}

func TestHTTPStatusErrorTruncatesLongMessage(t *testing.T) {
	got := (&HTTPStatusError{StatusCode: 500, Message: strings.Repeat("x", 5000)}).Error()
	if want := 300; len([]rune(got)) != want {
		t.Fatalf("error length = %d runes, want %d", len([]rune(got)), want)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("error = %q, want ellipsis suffix", got)
	}
}

func TestHTTPStatusErrorPreservesNormalText(t *testing.T) {
	const message = "ordinary server message"
	if got := (&HTTPStatusError{StatusCode: 500, Message: message}).Error(); got != message {
		t.Fatalf("error = %q, want %q", got, message)
	}
}
