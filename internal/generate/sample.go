package generate

import (
	"errors"
	"fmt"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/random"
)

func Sample(source random.Source, buildResult alphabet.BuildResult, options Options) (Result, error) {
	if options.Attempts <= 0 {
		return Result{}, fmt.Errorf("attempts must be greater than zero, got %d", options.Attempts)
	}

	classes, err := classRequirementsFromBuildResult(buildResult, options.ClassMinimums)
	if err != nil {
		return Result{}, err
	}

	for attempt := 1; attempt <= options.Attempts; attempt++ {
		candidate, err := buildCandidate(source, options.MinLength, options.MaxLength, classes, buildResult.Union, options.Rules.RepeatTotal)
		if err != nil {
			if errors.Is(err, errCandidateLengthTooShort) {
				continue
			}

			return Result{
				Attempts: attempt,
			}, fmt.Errorf("sample candidate on attempt %d: %w", attempt, err)
		}

		return Result{
			Password: candidate,
			Attempts: attempt,
		}, nil
	}

	return Result{
			Attempts: options.Attempts,
		}, fmt.Errorf(
			"sample candidate: exhausted %d attempts while selecting a usable length",
			options.Attempts,
		)
}

func classRequirementsFromBuildResult(buildResult alphabet.BuildResult, classMinimums map[string]int) ([]classRequirement, error) {
	classes := make([]classRequirement, 0, len(buildResult.Classes))

	for _, class := range buildResult.Classes {
		minimum, ok := classMinimums[class.Name]
		if !ok {
			return nil, fmt.Errorf("missing minimum for class %q", class.Name)
		}

		classes = append(classes, classRequirement{
			name:     class.Name,
			alphabet: class.Alphabet,
			min:      minimum,
		})
	}

	return classes, nil
}
