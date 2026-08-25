package rules

import "unicode/utf8"

type repeatTotalViolation struct {
	offset int
	length int
}

func checkRepeatTotal(password []byte, repeatTotal bool) []repeatTotalViolation {
	if !repeatTotal || len(password) == 0 {
		return nil
	}

	seen := make(map[rune]struct{})
	var violations []repeatTotalViolation

	remaining := password
	runeOffset := 0

	for len(remaining) > 0 {
		r, size := utf8.DecodeRune(remaining)

		if _, exists := seen[r]; exists {
			violations = append(violations, repeatTotalViolation{
				offset: runeOffset,
				length: 1,
			})
		} else {
			seen[r] = struct{}{}
		}

		remaining = remaining[size:]
		runeOffset++
	}

	return violations
}
