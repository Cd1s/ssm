package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"ssm/internal/inventorytransaction"
	"ssm/internal/machinecontract"
)

func runKeysList() {
	pullIfChanged()
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	if len(v.Keys) == 0 {
		fmt.Println("No keys saved. Use 'ssm host add --key-file <path>' to import one safely.")
		return
	}

	for _, k := range v.Keys {
		lines := strings.Count(k.PrivateKey, "\n") + 1
		fmt.Printf("  %s (%d lines)\n", k.Name, lines)
	}
}

func runKeysRemove(name string) {
	pullIfChanged()
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	result, err := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
	}).RemoveSavedKey(v, name)
	if err != nil {
		var notFound *inventorytransaction.SavedKeyNotFoundError
		if errors.As(err, &notFound) {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: fmt.Sprintf("key %q not found", name),
				Alias:   name,
				Tool:    "legacy_not_found",
				Script:  "key",
			}))
		}
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	if machineJSON {
		writeMachineValue(result)
		return
	}
	fmt.Printf("Key \"%s\" removed.\n", name)
}
