package dictionary

import (
	"unicode"
	"unicode/utf8"
)

type dictionaryMatch struct {
	offset int
	length int
}

func searchTrie(password []byte, tree *trie, caseInsensitive bool, leet bool) []dictionaryMatch {
	if len(password) == 0 || tree == nil || tree.root == nil {
		return nil
	}

	var matches []dictionaryMatch

	remaining := password
	runeOffset := 0

	for len(remaining) > 0 {
		current := tree.root
		candidate := remaining
		matchLength := 0

		for len(candidate) > 0 {
			r, size := utf8.DecodeRune(candidate)

			if leet {
				r = normalizeLeetRune(r)
			}

			if caseInsensitive {
				r = unicode.ToLower(r)
			}

			next, exists := current.children[r]
			if !exists {
				break
			}

			current = next
			matchLength++

			if current.terminal {
				matches = append(matches, dictionaryMatch{
					offset: runeOffset,
					length: matchLength,
				})
			}

			candidate = candidate[size:]
		}

		_, size := utf8.DecodeRune(remaining)
		remaining = remaining[size:]
		runeOffset++
	}

	return matches
}
