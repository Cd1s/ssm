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
		jsonFlag := false
		switch len(args) {
		case 1:
		case 2:
			if args[1] != "--json" {
				sshctlUsageExit()
			}
			jsonFlag = true
		default:
			sshctlUsageExit()
		}
		unlock()
		if jsonFlag {
			runList(true)
		} else {
			runSSHCTLList()
		}
	case "run", "exec":
		if len(args) < 2 {
			sshctlUsageExit()
		}
		unlock()
		runSSHCTLRun(args[1], args[2:])
	case "plan":
		// sshctl plan <alias> <command...>
		if len(args) < 2 {
			sshctlUsageExit()
		}
		unlock()
		runSSHCTLPlan(args[1], args[2:])
	case "map":
		// sshctl map <targets> [options] [--] <command...>
		// targets: comma-separated aliases and/or globs
		if len(args) < 2 {
			sshctlUsageExit()
		}
		unlock()
		runSSHCTLMap(args[1:])
	case "check":
		jsonFlag := false
		switch len(args) {
		case 2:
		case 3:
			if args[2] != "--json" {
				sshctlUsageExit()
			}
			jsonFlag = true
		default:
			sshctlUsageExit()
		}
		unlock()
		runCheck(args[1], jsonFlag)
	case "doctor":
		unlock()
		runSSHCTLDoctor(args[1:])
	case "put":
		if len(args) != 4 {
			sshctlUsageExit()
		}
		unlock()
		runPut(args[1], args[2], args[3])
	case "get":
		if len(args) != 4 {
			sshctlUsageExit()
		}
		unlock()
		runGet(args[1], args[2], args[3])
	case "redirect", "alias-link":
		unlock()
		runRedirect(args[1:])
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
		unlock()
		if len(args) == 1 {
			runShell(args[0])
			return
		}
		runSSHCTLRun(args[0], args[1:])
	}
}

func runSSHCTLRun(alias string, cmdArgs []string) {
	spec, err := parseRemoteRunArgs(cmdArgs)
	if err != nil {
		if err.Error() == "help" {
			sshctlUsage()
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "sshctl: %s\n", err)
		sshctlUsageExit()
	}
	if len(spec.Scripts) > 1 {
		// Multi-script on one host: use map
		runMap([]string{alias}, spec)
		return
	}
	if len(spec.Scripts) == 1 && spec.Command == "" {
		spec.Command = spec.Scripts[0].Body
		spec.Scripts = nil
	}
	runExecSpec(alias, spec)
}

func runSSHCTLPlan(alias string, cmdArgs []string) {
	spec, err := parseRemoteRunArgs(cmdArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshctl: %s\n", err)
		sshctlUsageExit()
	}
	spec.Plan = true
	if !spec.JSON {
		// plan defaults to structured text; --json still works
	}
	runExecSpec(alias, spec)
}

func runSSHCTLMap(args []string) {
	// First non-flag token(s) until options: allow
	//   map host1,host2 -- cmd
	//   map 'web-*' -j 4 hostname
	//   map a,b --scripts s1.sh,s2.sh
	if len(args) == 0 {
		sshctlUsageExit()
	}
	// Collect targets until we hit a flag or --
	var targets []string
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" || strings.HasPrefix(a, "-") {
			break
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "sshctl map: missing target alias/pattern")
		sshctlUsageExit()
	}
	spec, err := parseRemoteRunArgs(args[i:])
	if err != nil {
		if err.Error() == "help" {
			sshctlUsage()
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "sshctl: %s\n", err)
		sshctlUsageExit()
	}
	// Single -f becomes scripts for multi or command for one - already handled in parse
	if len(spec.Scripts) == 0 && strings.TrimSpace(spec.Command) == "" {
		fmt.Fprintln(os.Stderr, "sshctl map: missing command or --scripts")
		sshctlUsageExit()
	}
	runMap(targets, spec)
}

func runSSHCTLDoctor(args []string) {
	alias := ""
	deep := false
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--deep":
			deep = true
		case "-h", "--help":
			sshctlUsage()
			os.Exit(0)
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "sshctl doctor: unknown option %s\n", args[i])
				sshctlUsageExit()
			}
			if alias != "" {
				sshctlUsageExit()
			}
			alias = args[i]
		}
	}
	runDoctor(alias, deep, asJSON)
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
	r := config.LoadRedirects()
	for old, neu := range r {
		fmt.Printf("%s\t->\t%s\n", old, neu)
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

	fmt.Printf("hosts=%d\nvault=%s\nsync=%s\nredirects=%d\nreuse=%s\n",
		count, vaultStatus, cloudStatus, len(config.LoadRedirects()), map[bool]string{true: "on", false: "off"}[os.Getenv("SSM_REUSE") != "0" && os.Getenv("SSM_REUSE") != "off"])
}

func sshctlUsage() {
	fmt.Print(`Usage:
  sshctl sync | pull | push
  sshctl list [--json]
  sshctl status
  sshctl check <alias> [--json]
  sshctl doctor [alias] [--deep] [--json]

  # Single host (agent-safe quoting)
  sshctl run <alias> <command...>
  sshctl run <alias> --json <command...>
  sshctl run <alias> --plan <command...>     # dry-run: show remote_command + risk
  sshctl plan <alias> <command...>          # same as run --plan
  sshctl run <alias> --secret NAME=val ...
  sshctl run <alias> --secret NAME=@file ...
  sshctl run <alias> --timeout 10s ...
  sshctl run <alias> --no-reuse ...
  sshctl run <alias> -s | -f script.sh
  sshctl run <alias> --scripts a.sh,b.sh    # parallel scripts on one host

  # Multi-host / multi-script parallel fleet
  sshctl map <alias|pattern>[,more...] [options] <command...>
  sshctl map 'web-*','api-*' -j 8 hostname
  sshctl map host1,host2 --scripts s1.sh,s2.sh   # host×script jobs in parallel
  sshctl map host --plan -j 4 'uname -s'

  sshctl put <alias> <local> <remote>       # file or directory tree
  sshctl get <alias> <remote> <local>
  sshctl redirect list|set <old> <new>|rm <old>
  sshctl shell <alias>

Env: SSM_TRACE=1  SSM_TIMEOUT=10s  SSM_REUSE=0  SSM_FORWARD_STDIN=1
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
