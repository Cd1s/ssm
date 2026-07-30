package main

import (
	"fmt"
	"strings"
)

func sshctlHelpRequest(args []string) (string, []string, bool) {
	if len(args) > 1 && args[0] == "help" {
		return args[1], args[2:], true
	}
	if len(args) > 1 {
		for _, arg := range args[1:] {
			if arg == "-h" || arg == "--help" {
				return args[0], args[1:], true
			}
		}
		if args[1] == "help" {
			return args[0], args[2:], true
		}
	}
	return "", nil, false
}

func sshctlCommandUsage(command string, args []string) {
	action := ""
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") && arg != "help" {
			action = arg
			break
		}
	}
	switch command {
	case "request":
		fmt.Print("Usage: sshctl request --file <request.json>|-\nReads one strict schema-v1 JSON object; always emits one JSON value.\nExample: sshctl request --file ./request.json\n")
	case "push":
		fmt.Print("Usage: sshctl [--json] push (--only <transaction-id> | --all)\n--only publishes one reviewed mutation; --all publishes the invocation-start pending set. Bare push is invalid.\nAn empty --all scope performs an identity-checked no-op or fails safely on divergence; it never publishes a full blob.\nExample: sshctl --json push --only tx_...\n")
	case "put":
		fmt.Print("Usage: sshctl put <alias> <local> <remote> [--resume=v1] [--sha256] [--timeout <duration>] [--json]\nResume v1 is explicit and regular-file-only; timeout uses Go durations such as 2m.\nExample: sshctl put app ./build.tgz /srv/build.tgz --sha256 --json\n")
	case "get":
		fmt.Print("Usage: sshctl get <alias> <remote> <local>\nDownloads a file or directory; local files publish atomically.\nExample: sshctl get app /var/log/app.log ./app.log\n")
	case "run", "exec", "plan":
		fmt.Print("Usage: sshctl ", command, " <alias> [--argv] <command> [args...]\nOptions: --json, --timeout <duration>, --no-reuse, --secret NAME=@file, -f <script>, -s, --preflight.\nFast repeated argv mode: sshctl run <alias> --stream [--refresh 30s]; send one JSON string array per line and receive NDJSON results.\nPrefer --argv for literals and -f for shell semantics; one-string shell commands are compatibility-only.\nExample: sshctl ", command, " app --argv hostname\n")
	case "map":
		fmt.Print("Usage: sshctl map <alias|glob>[,more...] [-j <workers>] [--json|--plan] [--argv] <command...>\nDefaults to bounded workers; one failure does not hide other results.\nExample: sshctl map 'web-*' -j 4 --json --argv hostname\n")
	case "host", "hosts":
		if action != "" {
			fmt.Printf("Usage: sshctl host %s <alias> [options] [--json] [--offline]\n", action)
		}
		hostCommandUsage()
	case "host-key", "known-hosts":
		fmt.Print("Usage:\n  sshctl host-key inspect <alias> [--json]\n  sshctl host-key accept <alias> --fingerprint SHA256:... --yes [--json]\nInspect before authentication; accept requires the exact observed fingerprint and explicit confirmation.\n")
	case "doctor":
		fmt.Print("Usage: sshctl doctor [alias] [--deep] [--json]\nReports vault/sync state; --deep adds remote health probes. No alias gives local diagnostics.\n")
	case "status":
		fmt.Print("Usage: sshctl [--json] status [--offline]\nChecks sync freshness by default; --offline explicitly uses cached local state.\n")
	case "sync", "pull":
		fmt.Printf("Usage: sshctl [--json] %s\nPulls the encrypted remote vault; no silent offline fallback.\n", command)
	case "redirect", "alias-link":
		fmt.Print("Usage:\n  sshctl redirect list [--json]\n  sshctl redirect set <old> <exact-target> [--json]\n  sshctl redirect rm <old> [--json]\nRedirects never auto-select an alias suggestion.\n")
	case "list":
		fmt.Print("Usage: sshctl [--json] list\nLists inventory aliases without secret values.\n")
	case "check":
		fmt.Print("Usage: sshctl check <alias> [--json]\nRuns a non-interactive SSH health probe for one exact alias.\n")
	default:
		sshctlUsage()
	}
}
