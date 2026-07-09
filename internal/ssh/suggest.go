package ssh

import (
	"strings"
	"unicode/utf8"
)

// SuggestNames returns up to limit connection names closest to query.
// Empty query or empty names yields nil.
func SuggestNames(query string, names []string, limit int) []string {
	if query == "" || len(names) == 0 || limit <= 0 {
		return nil
	}
	type scored struct {
		name  string
		score int
	}
	var best []scored
	q := strings.ToLower(query)
	for _, name := range names {
		n := strings.ToLower(name)
		d := levenshtein(q, n)
		// Also reward substring / prefix matches that agents often intend.
		if strings.Contains(n, q) || strings.Contains(q, n) {
			if d > 2 {
				d = 2
			}
		}
		// Ignore hopeless mismatches (allow longer distance for long names).
		maxDist := 3
		if l := utf8.RuneCountInString(q); l > 8 {
			maxDist = l / 3
			if maxDist < 3 {
				maxDist = 3
			}
			if maxDist > 6 {
				maxDist = 6
			}
		}
		if d > maxDist {
			continue
		}
		best = append(best, scored{name: name, score: d})
	}
	// Insertion sort by score then name (small N: vault host counts).
	for i := 1; i < len(best); i++ {
		j := i
		for j > 0 && (best[j].score < best[j-1].score || (best[j].score == best[j-1].score && best[j].name < best[j-1].name)) {
			best[j], best[j-1] = best[j-1], best[j]
			j--
		}
	}
	if len(best) > limit {
		best = best[:limit]
	}
	out := make([]string, len(best))
	for i, s := range best {
		out[i] = s.name
	}
	return out
}

func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	if len(ar) == 0 {
		return len(br)
	}
	if len(br) == 0 {
		return len(ar)
	}
	// Two-row DP.
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := cur[j-1] + 1
			sub := prev[j-1] + cost
			cur[j] = del
			if ins < cur[j] {
				cur[j] = ins
			}
			if sub < cur[j] {
				cur[j] = sub
			}
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}
