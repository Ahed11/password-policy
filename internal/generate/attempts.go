package generate

import (
	"errors"
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/rules"
)

var errPolicyTooStrict = errors.New("policy_too_strict")

func generateWithAttempts(source random.Source, minLength int, maxLength int, classes []classRequirement, unionAlphabet []rune, repeatTotal bool, attempts int, ruleOptions rules.Options) ([]byte, int, error) {
	if attempts <= 0 {
		return nil, 0, fmt.Errorf("attempts must be greater than zero, got %d", attempts)
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		result, stage, err := generateAttempt(source, minLength, maxLength, classes, unionAlphabet, repeatTotal, ruleOptions)
		if err != nil {
			switch stage {
			case attemptStageRules:
				return nil, attempt, fmt.Errorf("check candidate on attempt %d: %w", attempt, err)

			default:
				return nil, attempt, fmt.Errorf("generate candidate on attempt %d: %w", attempt, err)
			}
		}

		if !result.Accepted {
			continue
		}

		return result.Password, attempt, nil
	}

	return nil, attempts, fmt.Errorf("%w: exhausted %d attempts", errPolicyTooStrict, attempts)
}
