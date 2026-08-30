package policy

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/alphabet"
)

type classCapacity struct {
	name         string
	min          int
	alphabetSize int
}

func validateSolvability(config Config) []error {
	diagnostics := []error{}

	if len(config.Policy.Classes) == 0 {
		return diagnostics
	}

	classMinimumsValid := true

	for _, class := range config.Policy.Classes {
		if class.Min < 0 {
			classMinimumsValid = false
			break
		}
	}

	if config.Policy.Length.Max > 0 && classMinimumsValid {
		diagnostics = append(diagnostics, validateClassMinimumSum(config.Policy.Classes, config.Policy.Length.Max)...)
	}

	definitions := make([]alphabet.ClassDefinition, 0, len(config.Policy.Classes))

	for _, class := range config.Policy.Classes {
		definitions = append(
			definitions,
			alphabet.ClassDefinition{
				Name:     class.Name,
				Alphabet: class.Alphabet,
			},
		)
	}

	buildResult, buildErrors := alphabet.Build(definitions, config.Policy.Exclude)

	if len(buildErrors) != 0 || config.Policy.Length.Max <= 0 || !classMinimumsValid {
		return diagnostics
	}

	capacities := make([]classCapacity, 0, len(buildResult.Classes))

	for index, class := range buildResult.Classes {
		capacities = append(
			capacities,
			classCapacity{
				name:         class.Name,
				min:          config.Policy.Classes[index].Min,
				alphabetSize: len(class.Alphabet),
			},
		)
	}

	diagnostics = append(diagnostics, validateRepeatTotalCapacity(config.Policy.Forbid.RepeatTotal, config.Policy.Length.Max, len(buildResult.Union), capacities)...)

	return diagnostics
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
