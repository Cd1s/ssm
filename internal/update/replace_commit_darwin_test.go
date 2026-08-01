//go:build darwin

package update

import "testing"

// TestDarwinNativeReplacementSecurity is the focused native macOS gate for
// successful descriptor-copy commit and public, private, and final-entry races.
func TestDarwinNativeReplacementSecurity(t *testing.T) {
	t.Run("descriptor-copy success", testUnixDescriptorCopyCommitSuccess)
	t.Run("staging pathname substitution", testUnixDescriptorCopyCommitPathSubstitution)
	t.Run("private entry substitution", testUnixDescriptorCopyCommitEntrySubstitution)
	t.Run("final entry pathname substitution", func(t *testing.T) {
		testUnixCommitPostVerificationPathSubstitution(t, commitAuthenticatedUnixReplacementByCopy)
	})
	t.Run("final entry in-place mutation", func(t *testing.T) {
		testUnixCommitPostVerificationInPlaceMutation(t, commitAuthenticatedUnixReplacementByCopy)
	})
	t.Run("updater success", TestVerifiedReplacementPreservesPermissionsAndTarget)
	t.Run("updater commit-boundary substitution", TestUnixVerifiedReplacementRejectsCommitBoundarySubstitution)
}
