package ssh

import (
	"testing"
	"time"
)

// parseTimeout must not silently accept a malformed timeout as a different value.
func TestParseTimeoutRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"1.9", "30abc", "5 minutes", "0x10"} {
		d, err := parseTimeout(value)
		t.Logf("parseTimeout(%q) = %v, err=%v", value, d, err)
		if err == nil {
			t.Errorf("parseTimeout(%q) accepted a malformed duration as %v", value, d)
		}
	}
}

func TestParseTimeoutAcceptsValidValues(t *testing.T) {
	cases := map[string]time.Duration{
		"30":  30 * time.Second,
		"30s": 30 * time.Second,
		"1m":  time.Minute,
		"2h":  2 * time.Hour,
	}
	for value, want := range cases {
		d, err := parseTimeout(value)
		t.Logf("parseTimeout(%q) = %v, err=%v", value, d, err)
		if err != nil {
			t.Errorf("parseTimeout(%q) returned error %v", value, err)
			continue
		}
		if d != want {
			t.Errorf("parseTimeout(%q) = %v, want %v", value, d, want)
		}
	}

	// time.ParseDuration("0") succeeds and returns 0; callers ignore values <= 0.
	// Accept either an error or a zero duration.
	if d, err := parseTimeout("0"); err == nil && d != 0 {
		t.Errorf("parseTimeout(%q) = %v, want 0 or an error", "0", d)
	}
	if _, err := parseTimeout("-5"); err == nil {
		t.Errorf("parseTimeout(%q) accepted a non-positive duration", "-5")
	}
}
