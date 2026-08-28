package generate

import (
	"bytes"
	"io"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAttemptAccepted(t *testing.T) {
	buildResult := attemptTestBuildResult()

	result, err := GenerateAttempt(
		bytes.NewReader(nil),
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  0,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
			Rules: rules.Options{},
		},
	)

	require.NoError(t, err)

	assert.True(t, result.Accepted)
	assert.Equal(t, []byte{'a'}, result.Password)

	secret.Zero(result.Password)
}

func TestGenerateAttemptRuleRejected(t *testing.T) {
	buildResult := attemptTestBuildResult()

	result, err := GenerateAttempt(
		bytes.NewReader(nil),
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
			Rules: rules.Options{
				ContextValues: []string{
					"a",
				},
				ContextMinLength: 1,
			},
		},
	)

	require.NoError(t, err)

	assert.False(t, result.Accepted)
	assert.Nil(t, result.Password)
}

func TestGenerateAttemptLengthTooShortRejected(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	result, err := GenerateAttempt(
		bytes.NewReader(nil),
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			ClassMinimums: map[string]int{
				"letters": 2,
			},
			Rules: rules.Options{},
		},
	)

	require.NoError(t, err)

	assert.False(t, result.Accepted)
	assert.Nil(t, result.Password)
}

func TestGenerateAttemptMissingClassMinimum(t *testing.T) {
	result, err := GenerateAttempt(
		bytes.NewReader(nil),
		attemptTestBuildResult(),
		Options{
			MinLength:     1,
			MaxLength:     1,
			ClassMinimums: map[string]int{},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, `missing minimum for class "letters"`)

	assert.Equal(t, AttemptResult{}, result)
}

func TestGenerateAttemptSourceError(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	result, err := GenerateAttempt(
		bytes.NewReader(nil),
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
			Rules: rules.Options{},
		},
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, io.EOF)
	assert.ErrorContains(t, err, "generate candidate")

	assert.Equal(t, AttemptResult{}, result)
}

func TestGenerateAttemptNilSource(t *testing.T) {
	result, err := GenerateAttempt(
		nil,
		attemptTestBuildResult(),
		Options{
			MinLength: 1,
			MaxLength: 1,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "random source must not be nil")

	assert.Equal(t, AttemptResult{}, result)
}

func TestGenerateAttemptDoesNotUseAttemptsLimit(t *testing.T) {
	buildResult := attemptTestBuildResult()

	result, err := GenerateAttempt(
		bytes.NewReader(nil),
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,

			Attempts: -100,

			ClassMinimums: map[string]int{
				"letters": 1,
			},
			Rules: rules.Options{},
		},
	)

	require.NoError(t, err)

	assert.True(t, result.Accepted)
	assert.Equal(t, []byte{'a'}, result.Password)

	secret.Zero(result.Password)
}

func attemptTestBuildResult() alphabet.BuildResult {
	return alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a'},
			},
		},
		Union: []rune{'a'},
	}
}
