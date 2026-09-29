package main

import (
	"fmt"
	"strings"
)

var (
	helpTokens = []string{"help", "--help", "-h", "--version", "-v"}

	sharedCommands = []string{
		"pull", "push", "list", "host", "hosts", "run", "exec", "plan", "map", "check", "doctor",
		"put", "get", "redirect", "alias-link",
	}
	sshctlOnlyCommands = []string{"request", "sync", "host-key", "known-hosts", "shell", "status"}
	ssmOnlyCommands    = []string{
		"update", "remove", "keys", "ls", "import-json", "server", "register", "login", "logout",
		"pull-if-changed", "remote-hash",
	}

	// sshctlCommands are the subcommands of the sshctl entrypoint. A first
	// token outside this set is a host alias in the "sshctl <alias> <command>"
	// shorthand, whose remote argv is never scanned for sshctl options.
	sshctlCommands = commandSet(sharedCommands, sshctlOnlyCommands, helpTokens)

	// ssmCommands are the subcommands of the ssm entrypoint, which has no
	// alias shorthand.
	ssmCommands = commandSet(sharedCommands, ssmOnlyCommands, helpTokens)

	// knownCLICommands is the union of both entrypoints; ssm uses it so that
	// help for sshctl-only commands can point at sshctl.
	knownCLICommands = commandSet(sharedCommands, sshctlOnlyCommands, ssmOnlyCommands, helpTokens)
)

func commandSet(groups ...[]string) map[string]bool {
	set := map[string]bool{}
	for _, group := range groups {
		for _, name := range group {
			set[name] = true
		}
	}
	return set
}

func isKnownCommand(sshctl bool, command string) bool {
	if sshctl {
		return sshctlCommands[command]
	}
	return knownCLICommands[command]
}

// optionRegion returns the tokens after the command name that sshctl itself
// may interpret (-h, --help, --json, ...). For run/exec/plan/map and the
// "<alias> <command>" shorthand it stops at the remote argv boundary so the
// remote program's own -h/--help/--json are never captured. Other commands
// are scanned up to a bare "--".
func optionRegion(sshctl bool, command string, rest []string) []string {
	switch command {
	case "run", "exec", "plan":
		return rest[:runOptionEnd(rest)]
	case "map":
		return rest[:mapOptionEnd(rest)]
	}
	// Only sshctl has the "sshctl <alias> <command>" shorthand; an unknown
	// ssm command is an error whose output mode still honors --json.
	if sshctl && !isKnownCommand(sshctl, command) {
		return rest[:remoteArgvStart(rest)]
	}
	for i, arg := range rest {
		if arg == "--" {
			return rest[:i]
		}
	}
	return rest
}

func sshctlHelpRequest(args []string) (string, []string, bool) {
	return helpRequest(true, args)
}

func helpRequest(sshctl bool, args []string) (string, []string, bool) {
	if len(args) > 1 && args[0] == "help" {
		return args[1], args[2:], true
	}
	if len(args) > 1 {
		for _, arg := range optionRegion(sshctl, args[0], args[1:]) {
			if arg == "-h" || arg == "--help" {
				return args[0], args[1:], true
			}
		}
		// "<command> help", but not "sshctl <alias> help" where help is the
		// remote command.
		if args[1] == "help" && isKnownCommand(sshctl, args[0]) {
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
		fmt.Print("Usage: sshctl [--json] push (--only <transaction-id> | --all)\nReview pending transactions first. --only publishes one reviewed mutation; --all publishes only the non-empty invocation-start pending set. Bare push is invalid.\nAn empty --all scope performs an identity-checked no-op or fails safely on divergence; it never publishes a full blob. On divergence preserve sync-conflict.json and publishing-intent evidence, use --offline doctor, then run pull --adopt-remote <remote-sha256> --yes only after reviewing the exact remote identity; use reviewed ssm --offline --json import-json <reviewed-file> --merge and publish its transaction with --only.\nExample: sshctl --json push --only tx_...\n")
	case "put":
		fmt.Print("Usage: sshctl put <alias> <local> <remote> [--resume=v1] [--sha256] [--timeout <duration>] [--dir-mode <octal>] [--json]\nResume v1 is explicit and regular-file-only; timeout uses Go durations such as 2m. --sha256 needs sha256sum, shasum, or openssl on the remote host (otherwise integrity_tool_unavailable). Parent directories created by put default to 0755; --dir-mode overrides (uploaded files keep their own private temp-file + rename flow). A directory put whose remote tar fails reports stage remote_extract and may leave partial files; there is no per-file fallback unless the local tar is missing.\nJSON direct and request-v1 results identify direction and kind. Directory results report atomic=false, integrity=not_available, and resume=unsupported.\nExample: sshctl put app ./build.tgz /srv/build.tgz --sha256 --json\n")
	case "get":
		fmt.Print("Usage: sshctl get <alias> <remote> <local> [--sha256] [--timeout <duration>] [--json]\nFlags may appear in any position. --sha256 verifies a regular file against the remote digest (sha256sum, shasum, or openssl) before publishing; --timeout bounds the transfer; --resume is not supported for get. Downloads a file or directory; file results report direction=get, kind=file, bytes_received, and atomic=true. Directory results report direction=get, kind=directory, atomic=false, integrity=not_available, resume=unsupported, and omit bytes_received. Direct and request-v1 use the same fields.\nExample: sshctl get app /var/log/app.log ./app.log --sha256 --json\n")
	case "run", "exec", "plan":
		fmt.Print("Usage: sshctl ", command, " <alias> [--argv] <command> [args...]\nOptions: --json, --timeout <duration>, --no-reuse, --secret NAME=@file, -f <script>, -s, --shell <sh|bash|...>, --interpreter <program>, --preflight, --stdin, --no-stdin, --stdin-file <path>.\nNon-shell scripts: -f report.py --interpreter python3 -- a b runs \"python3 - a b\" with the script on stdin (one program name, absolute path, or env <name>; the program must read a script from stdin for -). Without --interpreter the script shebang picks a shell; --preflight is shell-only.\nStdin: --stdin forwards local stdin in every mode including --json; --no-stdin never forwards (like ssh -n; use it inside \"while read\" loops); --stdin-file <path> is \"< path\". Default: human mode forwards a non-terminal stdin, --json does not and reports stdin_forwarded:false when a pipe was left unread. SSM_FORWARD_STDIN=1|0 sets the default; flags win. A never-ending stdin pipe (CI/agent) makes a remote command that reads stdin wait forever: add --no-stdin or </dev/null. Not valid with -s/-f/--scripts, map, or --stream.\nFast repeated argv mode: sshctl run <alias> --stream [--refresh 30s]; send one JSON string array per line and receive compact NDJSON results. Online --refresh must be positive; --refresh=0 requires explicit global --offline. --offline is deprecated for reads: accepted for compatibility; reads are local by default and it now only suppresses background sync (with sync_mode strict it still skips the online refresh). In strict sync mode a refresh failure stops the stream; in the default local_first mode sync failures never stop it.\nPrefer --argv for literals and -f for shell semantics; one-string shell commands are compatibility-only.\nExample: sshctl ", command, " app --argv hostname\n")
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
		fmt.Print("Usage: sshctl [--json] status [--offline]\nIn the default local_first sync mode it reports the recorded sync outcome (remote_state, last_sync_error, next_sync_attempt, cache_age_seconds, inventory_stale, inventory_unsynced) without contacting the server and never fails because of sync; with sync_mode strict it refreshes online first. --offline (or SSM_OFFLINE=1) is deprecated for reads: accepted for compatibility; reads are local by default and it now only suppresses background sync (with sync_mode strict it still skips the online refresh and uses cached local state). Offline output reports pending transaction state and remote_state:not_checked.\n")
	case "sync", "pull":
		fmt.Printf("Usage: sshctl [--json] %[1]s [--adopt-remote <remote-sha256> --yes]\nExplicit and strict: failure is failure, with no silent offline fallback. Refuses to overwrite a local vault that diverged from the remote (conflict evidence is preserved), and fails with \"vault is busy\" if another ssm process holds the short vault write lock (retry).\nReviewed recovery: %[1]s --adopt-remote <remote-sha256> --yes replaces the local vault only after reviewing the exact remote identity, and is refused if the local vault changed after the conflict evidence was recorded (re-check with sshctl --offline --json doctor).\n", command)
	case "redirect", "alias-link":
		fmt.Print("Usage:\n  sshctl redirect list [--json]\n  sshctl redirect set <old> <exact-target> [--json]\n  sshctl redirect rm <old> [--json]\nRedirects never auto-select an alias suggestion.\n")
	case "list":
		fmt.Print("Usage: sshctl [--json] list\nLists inventory aliases without secret values. --offline is deprecated for reads: accepted for compatibility; it now only suppresses background sync.\n")
	case "check":
		fmt.Print("Usage: sshctl check <alias> [--json]\nRuns a non-interactive SSH health probe for one exact alias.\n")
	default:
		sshctlUsage()
	}
}

// ssmCommandUsage prints help for one subcommand of the ssm entrypoint. It is
// pure output: it never unlocks the vault, reads cloud configuration, touches
// the network, or writes configuration. login, register, and server keep their
// historical raw flag help through their own flag sets.
func ssmCommandUsage(command string, rest []string) {
	switch command {
	case "login":
		runLogin([]string{"--help"})
	case "register":
		runRegister([]string{"--help"})
	case "server":
		runServer([]string{"--help"})
	case "update":
		fmt.Print("Usage: ssm update [--major [--yes]]\nUpdates within the installed major version. --major reviews a major-version migration; --major --yes explicitly authorizes it. Digest and provenance verification are never bypassed.\n")
	case "logout":
		fmt.Print("Usage: ssm logout\nRemoves stored sync credentials.\n")
	case "remove":
		fmt.Print("Usage: ssm remove <alias>\nLegacy removal of one host; creates a reviewable pending transaction. Prefer: sshctl host remove <alias> --yes.\n")
	case "keys":
		fmt.Print("Usage:\n  ssm keys              list saved SSH keys\n  ssm keys remove <name> remove a saved SSH key\nsshctl has no keys command; use sshctl host commands with --key-file/--key.\n")
	case "import-json":
		fmt.Print("Usage: ssm [--json] import-json <path> (--merge | --replace --yes)\nImports reviewed JSON connections; every change creates a pending transaction; publish it with push --only <transaction-id>.\n")
	case "pull-if-changed":
		fmt.Print("Usage: ssm pull-if-changed\nDownloads the encrypted vault only when the remote hash changed.\n")
	case "remote-hash":
		fmt.Print("Usage: ssm remote-hash\nPrints the remote encrypted vault hash.\n")
	case "ls":
		sshctlCommandUsage("list", rest)
	case "request", "host-key", "known-hosts", "status", "sync", "shell":
		fmt.Printf("Note: ssm has no %s command; it exists only in sshctl. sshctl usage:\n", command)
		sshctlCommandUsage(command, rest)
	default:
		fmt.Printf("Note: ssm %s accepts the same syntax as sshctl %s.\n", command, command)
		sshctlCommandUsage(command, rest)
	}
}
