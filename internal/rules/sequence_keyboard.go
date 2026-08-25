package rules

import "unicode/utf8"

type keyboardSequenceViolation struct {
	offset int
	length int
	layout string
}

func checkKeyboardSequence(password []byte, limit int, layout keyboardLayout) []keyboardSequenceViolation {
	if limit <= 0 || len(password) == 0 {
		return nil
	}

	var violations []keyboardSequenceViolation

	remaining := password
	runeOffset := 0

	previousRow := -1
	previousColumn := -1
	hasPrevious := false

	direction := 0
	sequenceStart := 0
	sequenceLength := 0

	for len(remaining) > 0 {
		r, size := utf8.DecodeRune(remaining)

		row, column, found := findKeyboardPosition(layout, r)

		if !found {
			if sequenceLength >= limit {
				violations = append(violations, keyboardSequenceViolation{
					offset: sequenceStart,
					length: sequenceLength,
					layout: layout.name,
				})
			}

			hasPrevious = false
			direction = 0
			sequenceLength = 0

			remaining = remaining[size:]
			runeOffset++
			continue
		}

		if !hasPrevious {
			previousRow = row
			previousColumn = column
			hasPrevious = true

			sequenceStart = runeOffset
			sequenceLength = 1

			remaining = remaining[size:]
			runeOffset++
			continue
		}

		step := 0

		if row == previousRow {
			switch column {
			case previousColumn + 1:
				step = 1
			case previousColumn - 1:
				step = -1
			}
		}

		switch {
		case step == 0:
			if sequenceLength >= limit {
				violations = append(violations, keyboardSequenceViolation{
					offset: sequenceStart,
					length: sequenceLength,
					layout: layout.name,
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
				violations = append(violations, keyboardSequenceViolation{
					offset: sequenceStart,
					length: sequenceLength,
					layout: layout.name,
				})
			}

			direction = step
			sequenceStart = runeOffset - 1
			sequenceLength = 2
		}

		previousRow = row
		previousColumn = column

		remaining = remaining[size:]
		runeOffset++
	}

	if sequenceLength >= limit {
		violations = append(violations, keyboardSequenceViolation{
			offset: sequenceStart,
			length: sequenceLength,
			layout: layout.name,
		})
	}

	return violations
}

func findKeyboardPosition(layout keyboardLayout, r rune) (int, int, bool) {
	for rowIndex, row := range layout.rows {
		for columnIndex, key := range row {
			if key == r {
				return rowIndex, columnIndex, true
			}
		}
	}

	return 0, 0, false
}
