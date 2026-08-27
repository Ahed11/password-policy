package app

import (
	"context"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPassed(t *testing.T) {
	prepared := checkTestPrepared()

	evaluation, err := Check(context.Background(), prepared, []byte{'a', '1'})

	require.NoError(t, err)

	assert.True(t, evaluation.Passed)
	assert.True(t, evaluation.Length.Passed)
	require.Len(t, evaluation.Classes, 2)

	assert.True(t, evaluation.Classes[0].Passed)
	assert.True(t, evaluation.Classes[1].Passed)
	assert.Nil(t, evaluation.Violations)
}

func TestCheckLengthViolation(t *testing.T) {
	prepared := checkTestPrepared()
	prepared.Generate.MinLength = 3
	prepared.Generate.MaxLength = 4

	evaluation, err := Check(context.Background(), prepared, []byte{'a', '1'})

	require.NoError(t, err)

	assert.False(t, evaluation.Passed)

	assert.Equal(t, rules.LengthResult{
		Count:  2,
		Min:    3,
		Max:    4,
		Passed: false,
	}, evaluation.Length)

	assert.True(t, evaluation.Classes[0].Passed)
	assert.True(t, evaluation.Classes[1].Passed)
	assert.Nil(t, evaluation.Violations)
}

func TestCheckClassMinimumViolation(t *testing.T) {
	prepared := checkTestPrepared()

	evaluation, err := Check(context.Background(), prepared, []byte{'a', 'b'})

	require.NoError(t, err)

	assert.False(t, evaluation.Passed)
	assert.True(t, evaluation.Length.Passed)

	assert.Equal(t, []rules.ClassResult{
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
	}, evaluation.Classes)

	assert.Nil(t, evaluation.Violations)
}

func TestCheckRuleViolation(t *testing.T) {
	classMinimums := map[string]int{
		"lower": 1,
	}

	prepared := Prepared{
		Alphabet: alphabet.BuildResult{
			Classes: []alphabet.Class{
				{
					Name:     "lower",
					Alphabet: []rune{'a', 'b'},
				},
			},
			Union: []rune{'a', 'b'},
		},
		ClassMinimums: classMinimums,
		Rules: rules.Options{
			RepeatRun: 2,
		},
		Generate: generate.Options{
			MinLength:     3,
			MaxLength:     3,
			Attempts:      1,
			ClassMinimums: classMinimums,
			Rules: rules.Options{
				RepeatRun: 2,
			},
		},
	}

	evaluation, err := Check(context.Background(), prepared, []byte{'a', 'a', 'a'})

	require.NoError(t, err)

	assert.False(t, evaluation.Passed)
	assert.True(t, evaluation.Length.Passed)
	assert.True(t, evaluation.Classes[0].Passed)

	assert.Equal(t, []rules.Violation{
		{
			Rule:   "repeat_run",
			Offset: 0,
			Length: 3,
		},
	}, evaluation.Violations)
}

func TestCheckCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	evaluation, err := Check(ctx, checkTestPrepared(), []byte{'a', '1'})

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, rules.Evaluation{}, evaluation)
}

func TestCheckRulesError(t *testing.T) {
	classMinimums := map[string]int{
		"letters": 1,
	}

	prepared := Prepared{
		Alphabet: alphabet.BuildResult{
			Classes: []alphabet.Class{
				{
					Name:     "letters",
					Alphabet: []rune{'q', 'w', 'e'},
				},
			},
			Union: []rune{'q', 'w', 'e'},
		},
		ClassMinimums: classMinimums,
		Rules: rules.Options{
			KeyboardSequence: 3,
			KeyboardLayouts: []string{
				"unknown",
			},
		},
		Generate: generate.Options{
			MinLength:     3,
			MaxLength:     3,
			Attempts:      1,
			ClassMinimums: classMinimums,
		},
	}

	evaluation, err := Check(context.Background(), prepared, []byte{'q', 'w', 'e'})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "check password against policy")
	assert.ErrorContains(t, err, `unknown keyboard layout "unknown"`)

	assert.Equal(t, rules.Evaluation{}, evaluation)
}

func TestCheckInvalidUTF8(t *testing.T) {
	evaluation, err := Check(context.Background(), checkTestPrepared(), []byte{0xff})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "password is not valid UTF-8")

	assert.Equal(t, rules.Evaluation{}, evaluation)
}

func checkTestPrepared() Prepared {
	classMinimums := map[string]int{
		"lower":  1,
		"digits": 1,
	}

	ruleOptions := rules.Options{}

	return Prepared{
		Alphabet: alphabet.BuildResult{
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
		},
		ClassMinimums: classMinimums,
		Rules:         ruleOptions,
		Generate: generate.Options{
			MinLength:     2,
			MaxLength:     2,
			Attempts:      1,
			ClassMinimums: classMinimums,
			Rules:         ruleOptions,
		},
	}
}
