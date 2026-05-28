package update

import "testing"

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		latest  string
		current string
		want    bool
	}{
		{"v1.0.1", "1.0.0", true},
		{"v1.0.0", "1.0.0", false},
		{"1.2.0", "1.1.9", true},
		{"v0.9.9", "1.0.0", false},
	}
	for _, tc := range cases {
		if got := newerVersion(tc.latest, tc.current); got != tc.want {
			t.Fatalf("newerVersion(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}
