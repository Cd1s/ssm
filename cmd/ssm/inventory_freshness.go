package main

import (
	"fmt"
	"os"
	"time"

	"ssm/internal/synctransaction"
)

// inventoryStale records, for the running command, that the local inventory
// cache is older than the configured stale_after. Structured run results carry
// it as the additive inventory_stale field.
var (
	inventoryStale bool
	staleWarned    bool
)

// noteInventoryFreshness is the sync transaction's observer for every
// successful inventory read. It stores staleness and, for human output, prints
// one warning line on stderr so stdout stays clean.
func noteInventoryFreshness(facts synctransaction.Facts) {
	inventoryStale = facts.Stale
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
