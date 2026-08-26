package rules

import (
	"unicode"
	"unicode/utf8"
)

type contextViolation struct {
	offset int
	length int
}

func checkContext(password []byte, values []string, minLength int, caseInsensitive bool, leet bool) []contextViolation {
	if len(password) == 0 || len(values) == 0 || minLength <= 0 {
		return nil
	}

	var violations []contextViolation
	seen := make(map[contextViolation]struct{})

	for _, value := range values {
		contextRunes := normalizeContextValue(value, caseInsensitive, leet)

		if len(contextRunes) < minLength {
			continue
		}

		for start := 0; start+minLength <= len(contextRunes); start++ {
			window := contextRunes[start : start+minLength]

			for _, violation := range findContextWindowMatches(password, window, false, caseInsensitive, leet) {
				if _, exists := seen[violation]; exists {
					continue
				}

				seen[violation] = struct{}{}
				violations = append(violations, violation)
			}

			for _, violation := range findContextWindowMatches(password, window, true, caseInsensitive, leet) {
				if _, exists := seen[violation]; exists {
					continue
				}

				seen[violation] = struct{}{}
				violations = append(violations, violation)
			}
		}
	}

	return violations
}

func normalizeContextValue(value string, caseInsensitive bool, leet bool) []rune {
	result := make([]rune, 0, utf8.RuneCountInString(value))

	for _, r := range value {
		result = append(result, normalizeContextRune(r, caseInsensitive, leet))
	}

	return result
}

func normalizeContextRune(r rune, caseInsensitive bool, leet bool) rune {
	if leet {
		switch r {
		case '4':
			r = 'a'
		case '3':
			r = 'e'
		case '1':
			r = 'l'
		case '0':
			r = 'o'
		case '5', '$':
			r = 's'
		case '@':
			r = 'a'
		case '7':
			r = 't'
		}
	}

	if caseInsensitive {
		r = unicode.ToLower(r)
	}

	return r
}

func findContextWindowMatches(password []byte, window []rune, reversed bool, caseInsensitive bool, leet bool) []contextViolation {
	if len(window) == 0 {
		return nil
	}

	var matches []contextViolation

	remaining := password
	runeOffset := 0

	for len(remaining) > 0 {
		if matchesContextWindow(remaining, window, reversed, caseInsensitive, leet) {
			matches = append(matches, contextViolation{
				offset: runeOffset,
				length: len(window),
			})
		}

		_, size := utf8.DecodeRune(remaining)
		remaining = remaining[size:]
		runeOffset++
	}

	return matches
}

func matchesContextWindow(password []byte, window []rune, reversed bool, caseInsensitive bool, leet bool) bool {
	candidate := password

	for i := 0; i < len(window); i++ {
		if len(candidate) == 0 {
			return false
		}

		r, size := utf8.DecodeRune(candidate)
		r = normalizeContextRune(r, caseInsensitive, leet)

		expectedIndex := i
		if reversed {
			expectedIndex = len(window) - 1 - i
		}

		if r != window[expectedIndex] {
			return false
		}

		candidate = candidate[size:]
	}

	return true
}
