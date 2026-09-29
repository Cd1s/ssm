package main

import (
	"fmt"
	"os"

	"ssm/internal/cloud"
	"ssm/internal/inventorytransaction"
	"ssm/internal/synctransaction"
)

// backgroundSyncFlag is the hidden argument of `sshctl sync` that marks the
// detached process started by an inventory read whose automatic sync is due.
// It is deliberately absent from help output.
const backgroundSyncFlag = "--background"

// isBackgroundSyncInvocation reports whether args (after global flags) request
// the detached background sync.
func isBackgroundSyncInvocation(args []string) bool {
	return len(args) == 2 && (args[0] == "sync" || args[0] == "pull") && args[1] == backgroundSyncFlag
}

// spawnBackgroundSync starts the detached background sync process. It returns
// as soon as the process has been started and never waits for it.
func spawnBackgroundSync() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	return startDetachedBackgroundSync(executable)
}

// runBackgroundSync is the body of the detached process. It produces no
// output and always exits 0: its result belongs to sync-state.json, and no
// terminal is waiting for it.
//
// Mutual exclusion: the process observes the remote identity and downloads a
// changed vault without any lock (bounded by a short HTTP timeout), then takes
// the vault write lock only to re-read local identity and replace the file, so
// a hung service can never make a command wait. Local mutations and
// publication finalization use the same lock, so none can overwrite another.
// While the lock is held, an unreconciled publishing intent (a publication in
// flight or awaiting recovery) leaves local state alone. The process never
// publishes and never overwrites divergent state.
func runBackgroundSync() {
	cloud.SetRequestTimeout(synctransaction.BackgroundRequestTimeout)
	transaction := syncTransaction(false)
	_ = transaction.BackgroundSync(func() (func(), error) {
		session, err := inventorytransaction.BeginVaultWrite()
		if err != nil {
			return nil, synctransaction.ErrBackgroundSkipped
		}
		if inventorytransaction.HasPublishingIntent() {
			_ = session.Close()
			return nil, synctransaction.ErrBackgroundSkipped
		}
		return func() { _ = session.Close() }, nil
	})
	os.Exit(0)
}
