package main

import (
	"fmt"
	"os"
	"strings"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

func runKeysList() {
	v, err := loadVault()
	if err != nil {
		printError(err)
		os.Exit(1)
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
		printError(err)
		os.Exit(1)
	}

	found := -1
	for i, k := range v.Keys {
		if k.Name == name {
			found = i
			break
		}
	}
	if found == -1 {
		fmt.Printf("Key \"%s\" not found.\n", name)
		os.Exit(1)
	}

	v.Keys = append(v.Keys[:found], v.Keys[found+1:]...)
	if err := config.Save(v, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}
	cloud.AutoPush()
	fmt.Printf("Key \"%s\" removed.\n", name)
}
