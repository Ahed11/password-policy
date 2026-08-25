package rules

import "unicode/utf8"

type repeatRunViolation struct {
	offset int
	length int
}

func checkRepeatRun(password []byte, repeatRun int) []repeatRunViolation {
	if repeatRun <= 0 || len(password) == 0 {
		return nil
	}

	var violations []repeatRunViolation

	remaining := password

	var current rune
	runStart := 0
	runLength := 0
	runeOffset := 0

	for len(remaining) > 0 {
		r, size := utf8.DecodeRune(remaining)

		if runLength == 0 {
			current = r
			runStart = runeOffset
			runLength = 1
		} else if r == current {
			runLength++
		} else {
			if runLength > repeatRun {
				violations = append(violations, repeatRunViolation{
					offset: runStart,
					length: runLength,
				})
			}

			current = r
			runStart = runeOffset
			runLength = 1
		}

		remaining = remaining[size:]
		runeOffset++
	}

	if runLength > repeatRun {
		violations = append(violations, repeatRunViolation{
			offset: runStart,
			length: runLength,
		})
	}

	return violations
}
