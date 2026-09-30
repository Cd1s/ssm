package ssh

import "testing"

func TestReuseEnabledMatchesStatusContract(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"0", false}, {"off", false}, {"false", false}, {"no", false},
		{"disable", false}, {"disabled", false}, {"1", true}, {"on", true}, {"", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("SSM_REUSE", tc.value)
			if got := ReuseEnabled(); got != tc.want {
				t.Fatalf("ReuseEnabled() = %t, want %t", got, tc.want)
			}
		})
	}
}
