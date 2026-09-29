package inventorytransaction

import "time"

// SetMutationLockWait shortens the vault write lock wait for a test and
// returns a function restoring it.
func SetMutationLockWait(wait time.Duration) func() {
	previous := mutationLockWait
	mutationLockWait = wait
	return func() { mutationLockWait = previous }
}
