package generate

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/rules"
)

var ErrPolicyTooStrict = errPolicyTooStrict

type Result struct {
	Password []byte
	Attempts int
}

type Options struct {
	MinLength     int
	MaxLength     int
	Attempts      int
	ClassMinimums map[string]int
	Rules         rules.Options
}

func Generate(source random.Source, buildResult alphabet.BuildResult, options Options) (Result, error) {
	classes := make([]classRequirement, 0, len(buildResult.Classes))

	for _, class := range buildResult.Classes {
		minimum, ok := options.ClassMinimums[class.Name]
		if !ok {
			return Result{}, fmt.Errorf(
				"missing minimum for class %q",
				class.Name,
			)
		}

		classes = append(classes, classRequirement{
			name:     class.Name,
			alphabet: class.Alphabet,
			min:      minimum,
		})
	}

	password, attemptsUsed, err := generateWithAttempts(source, options.MinLength, options.MaxLength, classes, buildResult.Union, options.Rules.RepeatTotal, options.Attempts, options.Rules)
	if err != nil {
		return Result{
			Attempts: attemptsUsed,
		}, err
	}

	return Result{
		Password: password,
		Attempts: attemptsUsed,
	}, nil
}
