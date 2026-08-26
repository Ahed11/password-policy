package generate

import (
	"io"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource([]byte{0})

	result, err := Generate(
		source,
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  3,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
			Rules: rules.Options{},
		},
	)

	require.NoError(t, err)

	assert.Equal(t, []byte{'a'}, result.Password)
	assert.Equal(t, 1, result.Attempts)
	assert.Equal(t, 1, source.readCalls)
}

func TestGenerateRepeatTotal(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource([]byte{0, 0})

	result, err := Generate(
		source,
		buildResult,
		Options{
			MinLength: 2,
			MaxLength: 2,
			Attempts:  1,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
			Rules: rules.Options{
				RepeatTotal: true,
			},
		},
	)

	require.NoError(t, err)

	assert.Equal(t, []byte{'b', 'a'}, result.Password)
	assert.Equal(t, 1, result.Attempts)
	assert.Equal(t, 2, source.readCalls)
}

func TestGenerateMissingClassMinimum(t *testing.T) {
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

	result, err := Generate(
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

	assert.Nil(t, result.Password)
	assert.Equal(t, 0, result.Attempts)
	assert.Equal(t, 0, source.readCalls)
}

func TestGeneratePolicyTooStrict(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource([]byte{0, 0})

	result, err := Generate(
		source,
		buildResult,
		Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  2,
			Rules: rules.Options{
				ContextValues:    []string{"a"},
				ContextMinLength: 1,
			},
		},
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPolicyTooStrict)

	assert.Nil(t, result.Password)
	assert.Equal(t, 2, result.Attempts)
	assert.Equal(t, 2, source.readCalls)
}

func TestGenerateSourceError(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	source := newCountingSource(nil)

	result, err := Generate(
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
	assert.ErrorIs(t, err, io.EOF)

	assert.Nil(t, result.Password)
	assert.Equal(t, 1, result.Attempts)
	assert.Equal(t, 1, source.readCalls)
}
