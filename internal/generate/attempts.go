package generate

import (
	"errors"
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
)

var errPolicyTooStrict = errors.New("policy_too_strict")

func generateWithAttempts(source random.Source, minLength int, maxLength int, classes []classRequirement, unionAlphabet []rune, repeatTotal bool, attempts int, ruleOptions rules.Options) ([]byte, int, error) {
	if attempts <= 0 {
		return nil, 0, fmt.Errorf("attempts must be greater than zero, got %d", attempts)
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		candidate, err := buildCandidate(source, minLength, maxLength, classes, unionAlphabet, repeatTotal)
		if err != nil {
			if errors.Is(err, errCandidateLengthTooShort) {
				continue
			}

			return nil, attempt, fmt.Errorf("generate candidate on attempt %d: %w", attempt, err)
		}

		violations, err := rules.Check(candidate, ruleOptions)
		if err != nil {
			secret.Zero(candidate)

			return nil, attempt, fmt.Errorf("check candidate on attempt %d: %w", attempt, err)
		}

		if len(violations) == 0 {
			return candidate, attempt, nil
		}

		secret.Zero(candidate)
	}

	return nil, attempts, fmt.Errorf("%w: exhausted %d attempts", errPolicyTooStrict, attempts)
}
