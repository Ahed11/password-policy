package policy

import (
	"fmt"
)

type classCapacity struct {
	name         string
	min          int
	alphabetSize int
}

func validateClassMinimumSum(classes []Class, lengthMax int) []error {
	var diagnostics []error

	sum := 0

	for _, class := range classes {
		sum += class.Min
	}

	if sum > lengthMax {
		diagnostics = append(diagnostics, fmt.Errorf("sum of class minimums is %d, length.max is %d", sum, lengthMax))
	}

	return diagnostics
}

func validateRepeatTotalCapacity(repeatTotal bool, lengthMax int, unionAlphabetSize int, classes []classCapacity) []error {
	diagnostics := []error{}

	if !repeatTotal {
		return diagnostics
	}

	if lengthMax > unionAlphabetSize {
		diagnostics = append(diagnostics, fmt.Errorf("policy.length.max: value %d exceeds union alphabet size %d", lengthMax, unionAlphabetSize))
	}

	for _, class := range classes {
		if class.min > class.alphabetSize {
			diagnostics = append(diagnostics, fmt.Errorf("policy.classes[%q].min: value %d exceeds alphabet size %d", class.name, class.min, class.alphabetSize))
		}
	}

	return diagnostics
}