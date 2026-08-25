package rules

import (
	"unicode"
	"unicode/utf8"
)

type alphabetSequenceViolation struct {
	offset int
	length int
}

func checkAlphabetSequence(password []byte, limit int) []alphabetSequenceViolation {
	if limit <= 0 || len(password) == 0 {
		return nil
	}

	if limit == 1 {
		var violations []alphabetSequenceViolation

		remaining := password
		offset := 0

		for len(remaining) > 0 {
			_, size := utf8.DecodeRune(remaining)

			violations = append(violations, alphabetSequenceViolation{
				offset: offset,
				length: 1,
			})

			remaining = remaining[size:]
			offset++
		}

		return violations
	}

	var violations []alphabetSequenceViolation

	remaining := password

	first, size := utf8.DecodeRune(remaining)
	previous := unicode.ToLower(first)

	remaining = remaining[size:]

	direction := 0
	sequenceStart := 0
	sequenceLength := 1
	runeOffset := 1

	for len(remaining) > 0 {
		r, size := utf8.DecodeRune(remaining)
		current := unicode.ToLower(r)

		step := 0

		switch {
		case current == previous+1:
			step = 1
		case current == previous-1:
			step = -1
		}

		switch {
		case step == 0:
			if sequenceLength >= limit {
				violations = append(violations, alphabetSequenceViolation{
					offset: sequenceStart,
					length: sequenceLength,
				})
			}

			direction = 0
			sequenceStart = runeOffset
			sequenceLength = 1

		case direction == 0:
			direction = step
			sequenceStart = runeOffset - 1
			sequenceLength = 2

		case step == direction:
			sequenceLength++

		default:
			if sequenceLength >= limit {
				violations = append(violations, alphabetSequenceViolation{
					offset: sequenceStart,
					length: sequenceLength,
				})
			}

			direction = step
			sequenceStart = runeOffset - 1
			sequenceLength = 2
		}

		previous = current
		remaining = remaining[size:]
		runeOffset++
	}

	if sequenceLength >= limit {
		violations = append(violations, alphabetSequenceViolation{
			offset: sequenceStart,
			length: sequenceLength,
		})
	}

	return violations
}
