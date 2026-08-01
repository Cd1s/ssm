//go:build darwin

package update

import "testing"

// TestDarwinNativeReplacementSecurity is the focused native macOS gate for
// successful descriptor-copy commit and both public and private pathname races.
func TestDarwinNativeReplacementSecurity(t *testing.T) {
	t.Run("descriptor-copy success", testUnixDescriptorCopyCommitSuccess)
	t.Run("staging pathname substitution", testUnixDescriptorCopyCommitPathSubstitution)
	t.Run("private entry substitution", testUnixDescriptorCopyCommitEntrySubstitution)
	t.Run("updater success", TestVerifiedReplacementPreservesPermissionsAndTarget)
	t.Run("updater commit-boundary substitution", TestUnixVerifiedReplacementRejectsCommitBoundarySubstitution)
}
