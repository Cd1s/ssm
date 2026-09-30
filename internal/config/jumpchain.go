package config

import (
	"fmt"
	"strings"
)

// MaxJumpDepth is the largest number of jump hosts a chain may contain in
// front of its target.
const MaxJumpDepth = 5

// Reasons a jump chain is rejected.
const (
	JumpCycle   = "cycle"
	JumpDepth   = "depth"
	JumpMissing = "missing"
)

// JumpChainError describes why a proxy_jump chain cannot be resolved. Alias is
// the alias that made the chain invalid (the alias that closes the cycle, the
// alias that is missing, or the hop that exceeds the depth limit).
type JumpChainError struct {
	Reason string
	Alias  string
	Chain  []string
}

func (e *JumpChainError) Error() string {
	path := strings.Join(e.Chain, " -> ")
	switch e.Reason {
	case JumpCycle:
		return fmt.Sprintf("proxy_jump chain has a cycle at %q (%s)", e.Alias, path)
	case JumpDepth:
		return fmt.Sprintf("proxy_jump chain is deeper than %d jump hosts at %q (%s)", MaxJumpDepth, e.Alias, path)
	default:
		return fmt.Sprintf("proxy_jump alias %q does not exist (%s)", e.Alias, path)
	}
}

// ResolveJumpChain returns the connections to dial in order: every jump host
// first, the target last. A target without proxy_jump yields just itself.
// Redirects are applied to every proxy_jump alias. The chain must not contain
// a cycle, may hold at most MaxJumpDepth jump hosts, and every referenced alias
// must exist in v.
func ResolveJumpChain(v *Vault, target Connection) ([]Connection, error) {
	seen := map[string]bool{target.Name: true}
	names := []string{target.Name}
	var jumps []Connection
	next := strings.TrimSpace(target.ProxyJump)
	for next != "" {
		if len(jumps) >= MaxJumpDepth {
			return nil, &JumpChainError{Reason: JumpDepth, Alias: next, Chain: withAlias(names, next)}
		}
		conn, resolved, ok := ResolveAlias(v, next)
		if !ok {
			return nil, &JumpChainError{Reason: JumpMissing, Alias: next, Chain: withAlias(names, next)}
		}
		if seen[conn.Name] || seen[resolved] {
			return nil, &JumpChainError{Reason: JumpCycle, Alias: conn.Name, Chain: withAlias(names, conn.Name)}
		}
		seen[conn.Name], seen[resolved] = true, true
		names = withAlias(names, conn.Name)
		jumps = append([]Connection{conn}, jumps...)
		next = strings.TrimSpace(conn.ProxyJump)
	}
	return append(jumps, target), nil
}

func withAlias(names []string, alias string) []string {
	out := make([]string, 0, len(names)+1)
	out = append(out, names...)
	return append(out, alias)
}
