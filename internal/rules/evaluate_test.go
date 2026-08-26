package rules

import (
	"testing"
	"unicode/utf8"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluatePassed(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "lower",
				Alphabet: []rune{'a', 'b'},
			},
			{
				Name:     "digits",
				Alphabet: []rune{'1', '2'},
			},
		},
		Union: []rune{'a', 'b', '1', '2'},
	}

	result, err := Evaluate(
		[]byte{'a', '1', 'b', '2'},
		buildResult,
		EvaluationOptions{
			MinLength: 4,
			MaxLength: 4,
			ClassMinimums: map[string]int{
				"lower":  2,
				"digits": 2,
			},
			Rules: Options{},
		},
	)

	require.NoError(t, err)

	assert.True(t, result.Passed)

	assert.Equal(t, LengthResult{
		Count:  4,
		Min:    4,
		Max:    4,
		Passed: true,
	}, result.Length)

	assert.Equal(t, []ClassResult{
		{
			Name:    "lower",
			Count:   2,
			Minimum: 2,
			Passed:  true,
		},
		{
			Name:    "digits",
			Count:   2,
			Minimum: 2,
			Passed:  true,
		},
	}, result.Classes)

	assert.Nil(t, result.Violations)
}

func TestEvaluateLengthViolation(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "lower",
				Alphabet: []rune{'a'},
			},
			{
				Name:     "digits",
				Alphabet: []rune{'1'},
			},
		},
		Union: []rune{'a', '1'},
	}

	result, err := Evaluate(
		[]byte{'a', '1'},
		buildResult,
		EvaluationOptions{
			MinLength: 3,
			MaxLength: 4,
			ClassMinimums: map[string]int{
				"lower":  1,
				"digits": 1,
			},
			Rules: Options{},
		},
	)

	require.NoError(t, err)

	assert.False(t, result.Passed)

	assert.Equal(t, LengthResult{
		Count:  2,
		Min:    3,
		Max:    4,
		Passed: false,
	}, result.Length)

	assert.True(t, result.Classes[0].Passed)
	assert.True(t, result.Classes[1].Passed)
	assert.Nil(t, result.Violations)
}

func TestEvaluateClassMinimumViolation(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "lower",
				Alphabet: []rune{'a', 'b'},
			},
			{
				Name:     "digits",
				Alphabet: []rune{'1', '2'},
			},
		},
		Union: []rune{'a', 'b', '1', '2'},
	}

	result, err := Evaluate(
		[]byte{'a', 'b'},
		buildResult,
		EvaluationOptions{
			MinLength: 2,
			MaxLength: 2,
			ClassMinimums: map[string]int{
				"lower":  1,
				"digits": 1,
			},
			Rules: Options{},
		},
	)

	require.NoError(t, err)

	assert.False(t, result.Passed)
	assert.True(t, result.Length.Passed)

	assert.Equal(t, []ClassResult{
		{
			Name:    "lower",
			Count:   2,
			Minimum: 1,
			Passed:  true,
		},
		{
			Name:    "digits",
			Count:   0,
			Minimum: 1,
			Passed:  false,
		},
	}, result.Classes)

	assert.Nil(t, result.Violations)
}

func TestEvaluateRuleViolation(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "lower",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	result, err := Evaluate(
		[]byte{'a', 'a', 'a'},
		buildResult,
		EvaluationOptions{
			MinLength: 3,
			MaxLength: 3,
			ClassMinimums: map[string]int{
				"lower": 1,
			},
			Rules: Options{
				RepeatRun: 2,
			},
		},
	)

	require.NoError(t, err)

	assert.False(t, result.Passed)
	assert.True(t, result.Length.Passed)
	assert.True(t, result.Classes[0].Passed)

	assert.Equal(t, []Violation{
		{
			Rule:   "repeat_run",
			Offset: 0,
			Length: 3,
		},
	}, result.Violations)
}

func TestEvaluateUnicodeLengthAndClasses(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "symbols",
				Alphabet: []rune{'a', '😀'},
			},
		},
		Union: []rune{'a', '😀'},
	}

	var password []byte
	password = utf8.AppendRune(password, 'a')
	password = utf8.AppendRune(password, '😀')

	result, err := Evaluate(
		password,
		buildResult,
		EvaluationOptions{
			MinLength: 2,
			MaxLength: 2,
			ClassMinimums: map[string]int{
				"symbols": 2,
			},
			Rules: Options{},
		},
	)

	require.NoError(t, err)

	assert.True(t, result.Passed)

	assert.Equal(t, LengthResult{
		Count:  2,
		Min:    2,
		Max:    2,
		Passed: true,
	}, result.Length)

	assert.Equal(t, []ClassResult{
		{
			Name:    "symbols",
			Count:   2,
			Minimum: 2,
			Passed:  true,
		},
	}, result.Classes)
}

func TestEvaluateInvalidUTF8(t *testing.T) {
	result, err := Evaluate(
		[]byte{0xff},
		alphabet.BuildResult{},
		EvaluationOptions{
			MinLength: 1,
			MaxLength: 1,
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "password is not valid UTF-8")
	assert.Equal(t, Evaluation{}, result)
}

func TestEvaluateMissingClassMinimum(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "lower",
				Alphabet: []rune{'a'},
			},
		},
		Union: []rune{'a'},
	}

	result, err := Evaluate(
		[]byte{'a'},
		buildResult,
		EvaluationOptions{
			MinLength:     1,
			MaxLength:     1,
			ClassMinimums: map[string]int{},
			Rules:         Options{},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, `missing minimum for class "lower"`)
	assert.Equal(t, Evaluation{}, result)
}

func TestEvaluateRulesError(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "lower",
				Alphabet: []rune{'q', 'w', 'e'},
			},
		},
		Union: []rune{'q', 'w', 'e'},
	}

	result, err := Evaluate(
		[]byte{'q', 'w', 'e'},
		buildResult,
		EvaluationOptions{
			MinLength: 3,
			MaxLength: 3,
			ClassMinimums: map[string]int{
				"lower": 1,
			},
			Rules: Options{
				KeyboardSequence: 3,
				KeyboardLayouts: []string{
					"unknown",
				},
			},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "check prohibition rules")
	assert.ErrorContains(t, err, `unknown keyboard layout "unknown"`)

	assert.Equal(t, Evaluation{}, result)
}
