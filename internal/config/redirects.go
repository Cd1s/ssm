package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Redirects maps old alias names to target aliases (migration soft-links).
// Stored outside the encrypted vault so agents can manage links without
// rewriting connection secrets.
type Redirects map[string]string

func redirectsPath() string {
	return filepath.Join(Dir(), "redirects.json")
}

func LoadRedirects() Redirects {
	data, err := os.ReadFile(redirectsPath())
	if err != nil {
		return Redirects{}
	}
	var r Redirects
	if err := json.Unmarshal(data, &r); err != nil || r == nil {
		return Redirects{}
	}
	return r
}

func SaveRedirects(r Redirects) error {
	if r == nil {
		r = Redirects{}
	}
	if err := EnsurePrivateDir(Dir()); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return WritePrivateFile(redirectsPath(), append(data, '\n'))
}

// ResolveAlias follows redirect soft-links then looks up the vault connection.
// requested is the name the caller used; resolved is after redirects.
func ResolveAlias(v *Vault, requested string) (conn Connection, resolved string, ok bool) {
	if v == nil || requested == "" {
		return Connection{}, requested, false
	}
	r := LoadRedirects()
	name := requested
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		if seen[name] {
			return Connection{}, requested, false // cycle
		}
		seen[name] = true
		if next, has := r[name]; has && next != "" && next != name {
			name = next
			continue
		}
		break
	}
	for _, c := range v.Connections {
		if c.Name == name {
			return c, name, true
		}
	}
	// Direct hit without redirect already failed; also allow requested name
	// if redirects pointed nowhere useful.
	if name != requested {
		for _, c := range v.Connections {
			if c.Name == requested {
				return c, requested, true
			}
		}
	}
	return Connection{}, name, false
}

// MatchAliases expands comma-separated names and shell globs against vault
// connection names (not redirect keys). Redirects are applied later per name.
func MatchAliases(v *Vault, patterns []string) ([]string, error) {
	if v == nil {
		return nil, fmt.Errorf("nil vault")
	}
	var names []string
	for _, c := range v.Connections {
		names = append(names, c.Name)
	}
	// Also allow selecting by redirect source name.
	for src := range LoadRedirects() {
		names = append(names, src)
	}
	sort.Strings(names)
	names = uniqueStrings(names)

	var out []string
	seen := map[string]bool{}
	for _, raw := range patterns {
		for _, p := range splitComma(raw) {
			p = trimSpace(p)
			if p == "" {
				continue
			}
			matched := false
			for _, n := range names {
				ok, err := filepath.Match(p, n)
				if err != nil {
					return nil, fmt.Errorf("bad pattern %q: %w", p, err)
				}
				if ok {
					matched = true
					if !seen[n] {
						seen[n] = true
						out = append(out, n)
					}
				}
			}
			if !matched {
				// Keep literal so map can report alias_not_found per target.
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	return out, nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func splitComma(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
