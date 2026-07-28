package main

import (
	"fmt"
	"os"
	"strings"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func runKeysList() {
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
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	found := -1
	for i, k := range v.Keys {
		if k.Name == name {
			found = i
			break
		}
	}
	if found == -1 {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
			Message: fmt.Sprintf("key %q not found", name),
			Alias:   name,
			Tool:    "legacy_not_found",
			Script:  "key",
		}))
	}

	v.Keys = append(v.Keys[:found], v.Keys[found+1:]...)
	if err := config.Save(v, masterPass); err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	cloud.AutoPush()
	fmt.Printf("Key \"%s\" removed.\n", name)
}
