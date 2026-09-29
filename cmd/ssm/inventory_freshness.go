package main

import (
	"fmt"
	"os"
	"time"

	"ssm/internal/config"
	"ssm/internal/synctransaction"
)

// inventoryStale records, for the running command, that the local inventory
// cache is older than the configured stale_after. Structured run results carry
// it as the additive inventory_stale field.
var (
	inventoryStale bool
	staleWarned    bool
	modeWarned     bool
	unsyncedWarned bool
	// statusCommand makes the invalid-mode notice appear for `status --json`
	// too; other JSON commands keep stderr empty.
	statusCommand bool
)

// noteInventoryFreshness is the sync transaction's observer for every
// successful inventory read. It stores staleness and, for human output, prints
// one warning line on stderr so stdout stays clean.
func noteInventoryFreshness(facts synctransaction.Facts) {
	warnInvalidSyncMode()
	inventoryStale = facts.Stale
	warnUnsynced(facts)
	if !facts.Stale || machineJSON || streamMachine || staleWarned {
		return
	}
	staleWarned = true
	age := time.Duration(facts.CacheAge) * time.Second
	fmt.Fprintf(os.Stderr,
		"ssm: warning: inventory cache is %s old (last confirmed sync %s); run sshctl sync to refresh\n",
		formatStaleAge(age), facts.LastSync)
}

func formatStaleAge(age time.Duration) string {
	if age >= 48*time.Hour {
		return fmt.Sprintf("%d days", int(age/(24*time.Hour)))
	}
	return fmt.Sprintf("%d hours", int(age/time.Hour))
}

// warnInvalidSyncMode tells the user once that an unrecognized sync_mode was
// ignored, so a misspelled "strict" is not silently run as local_first.
func warnInvalidSyncMode() {
	if modeWarned || streamMachine || (machineJSON && !statusCommand) {
		return
	}
	source, value := config.LoadSettings().InvalidSyncMode()
	if source == "" {
		return
	}
	modeWarned = true
	fmt.Fprintf(os.Stderr,
		"ssm: warning: invalid %s %q (want local_first or strict); using local_first\n", source, value)
}

// warnUnsynced tells the user once that sync is configured but has never
// confirmed this inventory, so an empty or old vault is not mistaken for the
// remote one.
func warnUnsynced(facts synctransaction.Facts) {
	if !facts.Unsynced || unsyncedWarned || machineJSON || streamMachine {
		return
	}
	unsyncedWarned = true
	fmt.Fprintln(os.Stderr, "ssm: warning: inventory has not been synced yet; run sshctl sync to pull the remote vault")
}
