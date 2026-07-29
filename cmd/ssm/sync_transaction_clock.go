//go:build !compiled_cli_contract

package main

import "time"

func syncTransactionClock() func() time.Time {
	return nil
}
