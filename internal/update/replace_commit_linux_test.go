//go:build linux

package update

import "testing"

func TestUnixDescriptorLinkCommitFinalEntryRaces(t *testing.T) {
	t.Run("pathname substitution", func(t *testing.T) {
		testUnixCommitPostVerificationPathSubstitution(t, commitAuthenticatedUnixReplacement)
	})
	t.Run("in-place mutation", func(t *testing.T) {
		testUnixCommitPostVerificationInPlaceMutation(t, commitAuthenticatedUnixReplacement)
	})
	t.Run("post-rename validation mutation", func(t *testing.T) {
		testUnixCommitPostRenameValidationMutation(t, commitAuthenticatedUnixReplacement)
	})
	t.Run("rollback pathname change", func(t *testing.T) {
		testUnixCommitRollbackPathChange(t, commitAuthenticatedUnixReplacement)
	})
}
