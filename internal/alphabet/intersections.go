package alphabet

import (
	"fmt"
	"strconv"
	"strings"
)

type normalizedClass struct {
	name     string
	alphabet []rune
}

func intersectSortedRunes(left, right []rune) []rune {
	intersection := []rune{}

	leftIndex := 0
	rightIndex := 0

	for leftIndex < len(left) && rightIndex < len(right) {
		switch {
		case left[leftIndex] == right[rightIndex]:
			intersection = append(intersection, left[leftIndex])
			leftIndex++
			rightIndex++

		case left[leftIndex] < right[rightIndex]:
			leftIndex++

		default:
			rightIndex++
		}
	}

	return intersection
}

func validateClassIntersections(normalizedClasses []normalizedClass) []error {

	diagnostics := []error{}

	for i := range normalizedClasses {
		for j := i + 1; j < len(normalizedClasses); j++ {
			sharedRunes := intersectSortedRunes(normalizedClasses[i].alphabet, normalizedClasses[j].alphabet)
			if len(sharedRunes) == 0 {
				continue
			}

			diagnostics = append(diagnostics, fmt.Errorf("classes %q and %q share characters: %s", normalizedClasses[i].name, normalizedClasses[j].name, formatRunes(sharedRunes)))
		}
	}

	return diagnostics
}

func formatRunes(runes []rune) string {
	parts := make([]string, 0, len(runes))

	for _, r := range runes {
		parts = append(parts, strconv.Quote(string(r)))
	}

	return strings.Join(parts, ", ")
}
