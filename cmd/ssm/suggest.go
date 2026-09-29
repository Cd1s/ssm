package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	"ssm/internal/ssh"
)

// aliasShorthand is set when sshctl treats its first word as a host alias
// ("sshctl <alias> <command>"). connectionNotFound then checks, after the
// exact alias lookup missed, whether the word was really a mistyped command.
var aliasShorthand bool

// commandSuggestion is a hint for an unknown command word. Suggestions are
// only ever text: nothing is executed or selected on the caller's behalf.
type commandSuggestion struct {
	Hint       string
	Candidates []string
	// distance is the edit distance to the closest command; 0 marks an exact
	// name in another entrypoint or a known misguess.
	distance int
}

// misguessedCommands are names agents commonly guess that exist in neither
// entrypoint, with the closest real workflow.
var misguessedCommands = map[string]string{
	"vault": "`vault` is not a command in sshctl or ssm; inspect saved hosts with `sshctl host list`",
	"alias": "`alias` is not a command in sshctl or ssm; list aliases with `sshctl host list` and manage soft links with `sshctl redirect`",
}

// suggestCommand explains an unknown first word. sshctl selects which
// entrypoint is running.
func suggestCommand(sshctl bool, word string) (commandSuggestion, bool) {
	own, other, ownName, otherName := ssmCommands, sshctlCommands, "ssm", "sshctl"
	if sshctl {
		own, other, ownName, otherName = sshctlCommands, ssmCommands, "sshctl", "ssm"
	}
	lower := strings.ToLower(word)
	if hint, ok := misguessedCommands[lower]; ok {
		return commandSuggestion{Hint: hint}, true
	}
	if other[lower] && !own[lower] && !helpCommandToken(lower) {
		return commandSuggestion{Hint: fmt.Sprintf("`%s` is an %s command; run `%s %s ...`", word, otherName, otherName, lower)}, true
	}
	pool := map[string]string{}
	for name := range knownCLICommands {
		if !helpCommandToken(name) {
			pool[name] = otherName
			if own[name] {
				pool[name] = ownName
			}
		}
	}
	names := make([]string, 0, len(pool))
	for name := range pool {
		names = append(names, name)
	}
	best := nearestNames(lower, names, 3, normalizeCommandName)
	if len(best) == 0 {
		return commandSuggestion{}, false
	}
	first := best[0]
	quoted := make([]string, len(best))
	for i, name := range best {
		quoted[i] = fmt.Sprintf("`%s %s`", pool[name], name)
	}
	return commandSuggestion{
		Hint:       fmt.Sprintf("unknown command %q; did you mean %s?", word, strings.Join(quoted, " or ")),
		Candidates: best,
		distance:   commandDistance(lower, first),
	}, true
}

func helpCommandToken(name string) bool {
	for _, token := range helpTokens {
		if token == name {
			return true
		}
	}
	return false
}

func normalizeCommandName(name string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(name))
}

// nearestNames returns up to limit names within a small edit distance of word,
// closest first then alphabetical. Short words allow one edit, longer words two;
// words under three characters never match.
func nearestNames(word string, names []string, limit int, normalize func(string) string) []string {
	target := normalize(word)
	length := len([]rune(target))
	if length < 3 {
		return nil
	}
	maxDistance := 2
	if length <= 4 {
		maxDistance = 1
	}
	type scored struct {
		name     string
		distance int
	}
	var matches []scored
	for _, name := range names {
		if d := ssh.EditDistance(target, normalize(name)); d <= maxDistance {
			matches = append(matches, scored{name, d})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].distance != matches[j].distance {
			return matches[i].distance < matches[j].distance
		}
		return matches[i].name < matches[j].name
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.name
	}
	return out
}

// commandDistance is the edit distance used for both commands and aliases, so
// the two can be compared directly.
func commandDistance(a, b string) int {
	return ssh.EditDistance(normalizeCommandName(a), normalizeCommandName(b))
}

// aliasIsCloser reports whether some saved alias or redirect key is at least
// as close to word as the suggested command. A tie favors alias_not_found with
// alias candidates, the conservative answer when the word may be a mistyped
// alias.
func aliasIsCloser(word string, suggestion commandSuggestion, v *config.Vault, redirects config.Redirects) bool {
	if suggestion.distance == 0 {
		return false
	}
	if v != nil {
		for _, c := range v.Connections {
			if commandDistance(word, c.Name) <= suggestion.distance {
				return true
			}
		}
	}
	for name := range redirects {
		if commandDistance(word, name) <= suggestion.distance {
			return true
		}
	}
	return false
}

func exitUnknownCommand(sshctl bool, word string) {
	if suggestion, ok := suggestCommand(sshctl, word); ok {
		exitUnknownCommandSuggestion(sshctl, word, suggestion)
	}
	kind := machinecontract.UnknownSSMCommand
	if sshctl {
		kind = machinecontract.UnknownSSHCTLCommand
	}
	os.Exit(machinecontract.WriteClassified(machineJSON, kind, machinecontract.Details{Message: fmt.Sprintf("unknown command %q", word)}))
}

// exitUnknownCommandSuggestion reports unknown_command (exit 2) with the same
// hint and candidates in JSON and human output.
func exitUnknownCommandSuggestion(sshctl bool, word string, suggestion commandSuggestion) {
	kind := machinecontract.UnknownSSMCommand
	if sshctl {
		kind = machinecontract.UnknownSSHCTLCommand
	}
	os.Exit(machinecontract.WriteClassified(machineJSON, kind, machinecontract.Details{
		Message:    fmt.Sprintf("unknown command %q", word),
		Hint:       suggestion.Hint,
		Candidates: suggestion.Candidates,
	}))
}

// unknownRunOptionError is the run/exec/plan/map error for an option that
// parseRemoteRunArgs does not accept, with a suggestion when one is known.
func unknownRunOptionError(arg string) error {
	if suggestion := runOptionSuggestion(arg); suggestion != "" {
		return fmt.Errorf("unknown run option: %s; %s", arg, suggestion)
	}
	return fmt.Errorf("unknown run option: %s", arg)
}

// runOptionSuggestion returns a suggestion clause for an unknown run option, or
// "". Known misguesses are mapped explicitly; everything else is matched by
// edit distance against the real option tables so new options are picked up
// automatically.
func runOptionSuggestion(arg string) string {
	name, _, _ := strings.Cut(arg, "=")
	switch name {
	case "--script-file":
		return "did you mean -f <script> (or --file <script>)?"
	case "--fetch":
		return "to download files use `sshctl get <alias> <remote> <local>`"
	}
	if !strings.HasPrefix(name, "--") {
		return ""
	}
	var long []string
	for _, group := range [][]string{runValueOptions, runFlagOptions} {
		for _, option := range group {
			if strings.HasPrefix(option, "--") {
				long = append(long, option)
			}
		}
	}
	best := nearestNames(name, long, 2, func(s string) string { return strings.TrimLeft(s, "-") })
	if len(best) == 0 {
		return ""
	}
	for i, option := range best {
		if option == "--refresh" {
			best[i] = "--refresh (only valid together with --stream: `run <alias> --stream --refresh <duration>`)"
		}
	}
	return "did you mean " + strings.Join(best, " or ") + "?"
}
