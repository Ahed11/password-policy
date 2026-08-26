package generate

import (
	"io"
	"testing"

	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateWithAttemptsSuccessOnFirstAttempt(t *testing.T) {
	source := newCountingSource(nil)

	password, attemptsUsed, err := generateWithAttempts(source, 1, 1, nil, []rune{'a'}, false, 3, rules.Options{})

	require.NoError(t, err)
	assert.Equal(t, []byte{'a'}, password)
	assert.Equal(t, 1, attemptsUsed)
	assert.Equal(t, 0, source.readCalls)
}

func TestGenerateWithAttemptsRetriesAfterRuleViolation(t *testing.T) {
	source := newCountingSource([]byte{0, 128})

	password, attemptsUsed, err := generateWithAttempts(source, 1, 1, nil, []rune{'a', 'b'}, false, 3,
		rules.Options{
			ContextValues:    []string{"a"},
			ContextMinLength: 1,
		},
	)

	require.NoError(t, err)
	assert.Equal(t, []byte{'b'}, password)
	assert.Equal(t, 2, attemptsUsed)
	assert.Equal(t, 2, source.readCalls)
}

func TestGenerateWithAttemptsRetriesAfterLengthTooShort(t *testing.T) {
	classes := []classRequirement{
		{
			name:     "letters",
			alphabet: []rune{'a', 'b'},
			min:      2,
		},
	}

	source := newCountingSource([]byte{0, 128, 0, 128, 0})

	password, attemptsUsed, err := generateWithAttempts(source, 1, 2, classes, []rune{'a', 'b'}, false, 2, rules.Options{})

	require.NoError(t, err)
	assert.Equal(t, []byte{'b', 'a'}, password)
	assert.Equal(t, 2, attemptsUsed)
	assert.Equal(t, 5, source.readCalls)
}

func TestGenerateWithAttemptsSourceError(t *testing.T) {
	source := newCountingSource(nil)

	password, attemptsUsed, err := generateWithAttempts(source, 1, 1, nil, []rune{'a', 'b'}, false, 3, rules.Options{})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "generate candidate on attempt 1")
	assert.ErrorIs(t, err, io.EOF)

	assert.Nil(t, password)
	assert.Equal(t, 1, attemptsUsed)
	assert.Equal(t, 1, source.readCalls)
}

func TestGenerateWithAttemptsRulesError(t *testing.T) {
	source := newCountingSource(nil)

	password, attemptsUsed, err := generateWithAttempts(source, 1, 1, nil, []rune{'a'}, false, 3,
		rules.Options{
			KeyboardSequence: 3,
			KeyboardLayouts: []string{
				"unknown",
			},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "check candidate on attempt 1")
	assert.ErrorContains(t, err, `unknown keyboard layout "unknown"`)

	assert.Nil(t, password)
	assert.Equal(t, 1, attemptsUsed)
	assert.Equal(t, 0, source.readCalls)
}

func TestGenerateWithAttemptsPolicyTooStrict(t *testing.T) {
	source := newCountingSource([]byte{0, 0, 0})

	password, attemptsUsed, err := generateWithAttempts(source, 1, 1, nil, []rune{'a', 'b'}, false, 3,
		rules.Options{
			ContextValues:    []string{"a"},
			ContextMinLength: 1,
		},
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, errPolicyTooStrict)
	assert.ErrorContains(t, err, "exhausted 3 attempts")

	assert.Nil(t, password)
	assert.Equal(t, 3, attemptsUsed)
	assert.Equal(t, 3, source.readCalls)
}

func TestGenerateWithAttemptsInvalidAttempts(t *testing.T) {
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

			password, attemptsUsed, err := generateWithAttempts(source, 1, 1, nil, []rune{'a'}, false, test.attempts, rules.Options{})

			assert.Error(t, err)
			assert.ErrorContains(t, err, "attempts must be greater than zero")

			assert.Nil(t, password)
			assert.Equal(t, 0, attemptsUsed)
			assert.Equal(t, 0, source.readCalls)
		})
	}
}
