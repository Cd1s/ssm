package update

import (
	"errors"
	"testing"
)

func TestRecoveryDispositionsRemainDistinct(t *testing.T) {
	cause := errors.New("test-owned recovery cause")
	required := requireRecovery(cause)
	if !IsRecoveryRequired(required) || IsRecoveryBlocked(required) || !errors.Is(required, cause) {
		t.Fatalf("required disposition = %v", required)
	}
	blocked := blockOnRecoveryEvidence(cause)
	if IsRecoveryRequired(blocked) || !IsRecoveryBlocked(blocked) || !errors.Is(blocked, cause) {
		t.Fatalf("blocked disposition = %v", blocked)
	}
	preserved := preserveCanonical(cause)
	if !isCanonicalPreserved(preserved) || IsRecoveryRequired(preserved) || IsRecoveryBlocked(preserved) {
		t.Fatalf("preserved disposition = %v", preserved)
	}
	if got := blockOnRecoveryEvidence(required); got != required {
		t.Fatal("required recovery was reclassified")
	}
	if got := blockOnRecoveryEvidence(preserved); got != preserved {
		t.Fatal("canonical preservation was reclassified")
	}
}
