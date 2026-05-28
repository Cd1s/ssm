package main

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/tui"
)

func runKeysList() {
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	if len(v.Keys) == 0 {
		fmt.Println("No keys saved. Run 'ssm keys add' to add one.")
		return
	}

	for _, k := range v.Keys {
		lines := strings.Count(k.PrivateKey, "\n") + 1
		fmt.Printf("  %s (%d lines)\n", k.Name, lines)
	}
}

func runKeysAdd() string {
	fields := []tui.Field{
		{Label: "Name", Required: true, Placeholder: "production-key"},
		{Label: "Private key", Required: true, Placeholder: "paste your key here"},
	}

	p := tea.NewProgram(tui.NewFormModel("Add SSH key", fields), tea.WithAltScreen())
	result, err := p.Run()
	if err != nil {
		printError(err)
		return ""
	}

	fm := result.(tui.FormModel)
	if fm.Canceled || !fm.Done {
		return ""
	}

	name := fm.GetValue("Name")
	keyContent := fm.GetValue("Private key")

	v, _ := config.Load(masterPass)
	for _, k := range v.Keys {
		if k.Name == name {
			fmt.Printf("Key \"%s\" already exists.\n", name)
			return ""
		}
	}

	v.Keys = append(v.Keys, config.SSHKey{
		Name:       name,
		PrivateKey: keyContent,
	})

	if err := config.Save(v, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}
	cloud.AutoPush()
	fmt.Printf("Key \"%s\" added.\n", name)
	return name
}

func runKeysRemove(name string) {
	v, err := config.Load(masterPass)
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
