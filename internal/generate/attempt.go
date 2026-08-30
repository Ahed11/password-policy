package generate

import (
	"errors"
	"fmt"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
)

// AttemptResult содержит результат одной попытки генерации и признак принятия кандидата.
type AttemptResult struct {
	Password []byte
	Accepted bool
}

type attemptStage int

const (
	attemptStageNone attemptStage = iota
	attemptStageCandidate
	attemptStageRules
)

func generateAttempt(source random.Source, minLength int, maxLength int, classes []classRequirement, unionAlphabet []rune, repeatTotal bool, ruleOptions rules.Options) (AttemptResult, attemptStage, error) {
	if source == nil {
		return AttemptResult{}, attemptStageCandidate, fmt.Errorf("random source must not be nil")
	}

	candidate, err := buildCandidate(source, minLength, maxLength, classes, unionAlphabet, repeatTotal)
	if err != nil {
		if errors.Is(err, errCandidateLengthTooShort) {
			return AttemptResult{
				Accepted: false,
			}, attemptStageNone, nil
		}

		return AttemptResult{}, attemptStageCandidate, err
	}

	violations, err := rules.Check(candidate, ruleOptions)
	if err != nil {
		secret.Zero(candidate)

		return AttemptResult{}, attemptStageRules, err
	}

	if len(violations) > 0 {
		secret.Zero(candidate)

		return AttemptResult{
			Accepted: false,
		}, attemptStageNone, nil
	}

	return AttemptResult{
		Password: candidate,
		Accepted: true,
	}, attemptStageNone, nil
}

// GenerateAttempt выполняет одну попытку генерации кандидата и проверяет его по правилам политики.
func GenerateAttempt(source random.Source, buildResult alphabet.BuildResult, options Options) (AttemptResult, error) {
	if source == nil {
		return AttemptResult{}, fmt.Errorf("generate attempt: random source must not be nil")
	}

	classes, err := buildClassRequirements(buildResult, options.ClassMinimums)
	if err != nil {
		return AttemptResult{}, fmt.Errorf("generate attempt: %w", err)
	}

	result, stage, err := generateAttempt(source, options.MinLength, options.MaxLength, classes, buildResult.Union, options.Rules.RepeatTotal, options.Rules)
	if err != nil {
		switch stage {
		case attemptStageRules:
			return AttemptResult{}, fmt.Errorf("check candidate: %w", err)

		default:
			return AttemptResult{}, fmt.Errorf("generate candidate: %w", err)
		}
	}

	return result, nil
}

func buildClassRequirements(buildResult alphabet.BuildResult, classMinimums map[string]int) ([]classRequirement, error) {
	classes := make([]classRequirement, 0, len(buildResult.Classes))

	for _, class := range buildResult.Classes {
		minimum, ok := classMinimums[class.Name]
		if !ok {
			return nil, fmt.Errorf("missing minimum for class %q", class.Name)
		}

		classes = append(
			classes,
			classRequirement{
				name:     class.Name,
				alphabet: class.Alphabet,
				min:      minimum,
			},
		)
	}

	return classes, nil
}
