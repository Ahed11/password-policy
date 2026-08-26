package generate

import (
	"io"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSampleReturnsCandidateBeforeRuleFiltering(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource([]byte{0})

	result, err := Sample(
		source,
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			Rules: rules.Options{
				ContextValues:    []string{"a"},
				ContextMinLength: 1,
			},
		},
	)

	require.NoError(t, err)

	assert.Equal(t, []byte{'a'}, result.Password)
	assert.Equal(t, 1, result.Attempts)
	assert.Equal(t, 1, source.readCalls)

	violations, err := rules.Check(
		result.Password,
		rules.Options{
			ContextValues:    []string{"a"},
			ContextMinLength: 1,
		},
	)

	require.NoError(t, err)
	assert.NotEmpty(t, violations)

	secret.Zero(result.Password)
}

func TestSampleRetriesAfterLengthTooShort(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource([]byte{0, 128, 0, 128, 0})

	result, err := Sample(
		source,
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 2,
			Attempts:  2,
			ClassMinimums: map[string]int{
				"letters": 2,
			},
			Rules: rules.Options{},
		},
	)

	require.NoError(t, err)

	assert.Equal(t, []byte{'b', 'a'}, result.Password)
	assert.Equal(t, 2, result.Attempts)
	assert.Equal(t, 5, source.readCalls)

	secret.Zero(result.Password)
}

func TestSampleSourceError(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource(nil)

	result, err := Sample(
		source,
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  3,
			Rules:     rules.Options{},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "sample candidate on attempt 1")
	assert.ErrorIs(t, err, io.EOF)

	assert.Nil(t, result.Password)
	assert.Equal(t, 1, result.Attempts)
	assert.Equal(t, 1, source.readCalls)
}

func TestSampleMissingClassMinimum(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource(nil)

	result, err := Sample(
		source,
		buildResult,
		Options{
			MinLength:     1,
			MaxLength:     1,
			Attempts:      1,
			ClassMinimums: map[string]int{},
			Rules:         rules.Options{},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, `missing minimum for class "letters"`)

	assert.Equal(t, Result{}, result)
	assert.Equal(t, 0, source.readCalls)
}

func TestSampleInvalidAttempts(t *testing.T) {
	tests := []struct {
		name     string
		attempts int
	}{
		{
			name:     "zero",
			attempts: 0,
		},
		{
			name:     "negative",
			attempts: -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(nil)

			result, err := Sample(
				source,
				alphabet.BuildResult{
					Union: []rune{'a'},
				},
				Options{
					MinLength: 1,
					MaxLength: 1,
					Attempts:  test.attempts,
				},
			)

			assert.Error(t, err)
			assert.ErrorContains(t, err, "attempts must be greater than zero")

			assert.Equal(t, Result{}, result)
			assert.Equal(t, 0, source.readCalls)
		})
	}
}

func TestSampleExhaustsAttemptsWhenLengthAlwaysTooShort(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource(nil)

	result, err := Sample(
		source,
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  2,
			ClassMinimums: map[string]int{
				"letters": 2,
			},
			Rules: rules.Options{},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "exhausted 2 attempts while selecting a usable length")

	assert.Nil(t, result.Password)
	assert.Equal(t, 2, result.Attempts)
	assert.Equal(t, 0, source.readCalls)
}
