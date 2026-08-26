package generate

import (
	"bytes"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/require"
)

func TestGeneratedPasswordAlwaysPassesEvaluation(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "lower",
				Alphabet: []rune{'a', 'b', 'c', 'd', 'e', 'f'},
			},
			{
				Name:     "digits",
				Alphabet: []rune{'0', '1', '2', '3', '4', '5', '6', '7'},
			},
		},
		Union: []rune{
			'a', 'b', 'c', 'd', 'e', 'f',
			'0', '1', '2', '3', '4', '5', '6', '7',
		},
	}

	classMinimums := map[string]int{
		"lower":  2,
		"digits": 2,
	}

	ruleOptions := rules.Options{
		RepeatRun:   2,
		RepeatTotal: true,
	}

	generateOptions := Options{
		MinLength:     6,
		MaxLength:     8,
		Attempts:      10,
		ClassMinimums: classMinimums,
		Rules:         ruleOptions,
	}

	evaluationOptions := rules.EvaluationOptions{
		MinLength:     6,
		MaxLength:     8,
		ClassMinimums: classMinimums,
		Rules:         ruleOptions,
	}

	pattern := []byte{
		0,
		32,
		64,
		96,
		128,
		160,
		192,
		224,
	}

	source := bytes.NewReader(bytes.Repeat(pattern, 5000))

	const runs = 1000

	for i := 0; i < runs; i++ {
		result, err := Generate(source, buildResult, generateOptions)
		require.NoError(t, err)

		evaluation, err := rules.Evaluate(result.Password, buildResult, evaluationOptions)

		secret.Zero(result.Password)

		require.NoError(t, err)

		require.Truef(t, evaluation.Passed, "generated password failed evaluation on run %d: length=%+v classes=%+v violations=%+v", i, evaluation.Length, evaluation.Classes, evaluation.Violations)
	}
}
