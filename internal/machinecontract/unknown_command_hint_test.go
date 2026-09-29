package machinecontract

import "testing"

func TestUnknownCommandHintFromDetails(t *testing.T) {
	t.Parallel()
	for _, kind := range []Kind{UnknownSSHCTLCommand, UnknownSSMCommand} {
		custom := Classify(kind, Details{
			Message:    `unknown command "stauts"`,
			Hint:       "did you mean `sshctl status`?",
			Candidates: []string{"status"},
		})
		if custom.Error != "unknown_command" || custom.Exit != 2 || ProcessExit(custom) != 2 ||
			custom.Hint != "did you mean `sshctl status`?" || len(custom.Candidates) != 1 {
			t.Fatalf("%s custom hint: %+v", kind, custom)
		}
		fallback := Classify(kind, Details{Message: `unknown command "zzz"`})
		if fallback.Hint == "" || fallback.Hint == custom.Hint {
			t.Fatalf("%s must keep its static hint without a suggestion: %+v", kind, fallback)
		}
	}
	// Other kinds never take a caller-supplied hint.
	if got := Classify(AliasNotFound, Details{Hint: "x"}); got.Hint == "x" {
		t.Fatalf("hint override leaked into alias_not_found: %+v", got)
	}
}
