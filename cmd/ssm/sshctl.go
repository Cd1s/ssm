package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ssm/internal/config"
)

var (
	redactAssignmentPattern = regexp.MustCompile(`(?i)(["']?\b(?:password|passwd|pass|token|secret|private_key)\b["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}]+)`)
	redactBearerPattern     = regexp.MustCompile(`(?i)(["']?\bauthorization\b["']?\s*:\s*["']?bearer\s+)(?:"[^"]*"|'[^']*'|[^\s,}]+)`)
	privateKeyBlockPattern  = regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
)

func runSSHCTL(args []string) {
	parsed, err := parseGlobalArgs(args)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	args = parsed

	if masterPassFile == "" {
		masterPassFile = os.Getenv("SSM_MASTER_PASS_FILE")
	}
	if masterPassFile == "" {
		masterPassFile = filepath.Join(config.Dir(), "master.pass")
	}

	if len(args) == 0 {
		sshctlUsage()
		return
	}

	switch args[0] {
	case "sync", "pull":
		if len(args) != 1 {
			sshctlUsageExit()
		}
		runPull()
	case "push":
		if len(args) != 1 {
			sshctlUsageExit()
		}
		runPush()
	case "list":
		if len(args) != 1 {
			sshctlUsageExit()
		}
		unlock()
		runSSHCTLList()
	case "run":
		if len(args) < 3 {
			sshctlUsageExit()
		}
		unlock()
		runExec(args[1], strings.Join(args[2:], " "))
	case "put":
		if len(args) != 4 {
			sshctlUsageExit()
		}
		unlock()
		runPut(args[1], args[2], args[3])
	case "shell":
		if len(args) != 2 {
			sshctlUsageExit()
		}
		unlock()
		runShell(args[1])
	case "status":
		if len(args) != 1 {
			sshctlUsageExit()
		}
		unlock()
		runSSHCTLStatus()
	case "-h", "--help", "help":
		sshctlUsage()
	default:
		fmt.Fprintf(os.Stderr, "sshctl: unknown command: %s\n", args[0])
		sshctlUsageExit()
	}
}

func runSSHCTLList() {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	for _, c := range v.Connections {
		fmt.Printf("%s\t%s@%s:%d\n", c.Name, c.User, c.Host, c.Port)
	}
}

func runSSHCTLStatus() {
	pullIfChanged()
	count := 0
	v, err := config.Load(masterPass)
	if err == nil {
		count = len(v.Connections)
	}
	vaultStatus := "missing"
	if config.Exists() {
		vaultStatus = "present"
	}
	cloudStatus := "missing"
	if _, err := os.Stat(filepath.Join(config.Dir(), "cloud.json")); err == nil {
		cloudStatus = "configured"
	}

	fmt.Printf("hosts=%d\nvault=%s\nsync=%s\n", count, vaultStatus, cloudStatus)
}

func sshctlUsage() {
	fmt.Print(`Usage:
  sshctl sync
  sshctl pull
  sshctl push
  sshctl list
  sshctl run <alias> <command...>
  sshctl put <alias> <local> <remote>
  sshctl shell <alias>
  sshctl status
`)
}

func sshctlUsageExit() {
	sshctlUsage()
	os.Exit(2)
}

func redactError(err error) string {
	if err == nil {
		return ""
	}
	return redactString(err.Error())
}

func redactString(value string) string {
	out := privateKeyBlockPattern.ReplaceAllString(value, "<redacted-private-key>")
	out = redactBearerPattern.ReplaceAllString(out, "${1}***")
	out = redactAssignmentPattern.ReplaceAllString(out, "${1}<redacted>")
	out = strings.ReplaceAll(out, "-----BEGIN OPENSSH PRIVATE KEY-----", "<redacted-private-key>")
	return out
}

func printError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", redactError(err))
}
