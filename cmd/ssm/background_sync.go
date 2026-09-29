package main

import (
	"fmt"
	"os"
	"path/filepath"

	"ssm/internal/cloud"
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
func spawnBackgroundSync(claimToken string) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	return startDetachedBackgroundSync(executable, claimToken)
}

// backgroundClaimEnv carries the claim token from the process that claimed the
// attempt to the background process it starts.
const backgroundClaimEnv = "SSM_SYNC_CLAIM"

// runBackgroundSync is the body of the detached process. It produces no
// output and always exits 0: its result belongs to sync-state.json, and no
// terminal is waiting for it.
//
// The sync transaction owns the policy: it downloads outside any lock, takes
// the shared vault write lock only to compare identity and replace the file,
// and leaves local state alone while a publication awaits reconciliation.
func runBackgroundSync() {
	cloud.SetRequestTimeout(synctransaction.BackgroundRequestTimeout)
	_ = syncTransaction(false).BackgroundSync(os.Getenv(backgroundClaimEnv))
	os.Exit(0)
}

// backgroundEnvironment is the inherited environment with a relative
// SSM_CONFIG_DIR made absolute, because the child does not share the caller's
// working directory.
func backgroundEnvironment(claimToken string) []string {
	env := os.Environ()
	if claimToken != "" {
		env = append(env, backgroundClaimEnv+"="+claimToken)
	}
	if configured := os.Getenv("SSM_CONFIG_DIR"); configured != "" {
		if absolute, err := filepath.Abs(configured); err == nil {
			env = append(env, "SSM_CONFIG_DIR="+absolute)
		}
	}
	return env
}
