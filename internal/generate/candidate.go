package generate

import (
	"errors"
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
)

var errCandidateLengthTooShort = errors.New("candidate length is too short for class minimums")

func buildCandidate(source random.Source, minLength int, maxLength int, classes []classRequirement, unionAlphabet []rune, repeatTotal bool) ([]byte, error) {
	targetLength, err := chooseLength(source, minLength, maxLength)
	if err != nil {
		return nil, fmt.Errorf("build candidate: %w", err)
	}

	minimumCount := 0
	for _, class := range classes {
		minimumCount += class.min
	}

	if targetLength < minimumCount {
		return nil, fmt.Errorf("%w: target length %d, class minimum total %d", errCandidateLengthTooShort, targetLength, minimumCount)
	}

	selected, used, err := pickClassMinimums(source, classes, repeatTotal)
	if err != nil {
		return nil, fmt.Errorf("build candidate class minimums: %w", err)
	}

	values, err := fillToLength(source, selected, used, unionAlphabet, targetLength, repeatTotal)
	if err != nil {
		return nil, fmt.Errorf("build candidate fill to length: %w", err)
	}

	if err := shuffleRunes(source, values); err != nil {
		return nil, fmt.Errorf("build candidate: %w", err)
	}

	return encodeRunes(values), nil
}
