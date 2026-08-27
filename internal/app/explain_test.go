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

func TestExplainPassed(t *testing.T) {
	explanation, err := Explain(context.Background(), checkTestPrepared(), []byte{'a', '1'})

	require.NoError(t, err)

	assert.True(t, explanation.Passed)

	assert.Equal(t, rules.LengthResult{
		Count:  2,
		Min:    2,
		Max:    2,
		Passed: true,
	}, explanation.Length)

	assert.Equal(t, []rules.ClassResult{
		{
			Name:    "lower",
			Count:   1,
			Minimum: 1,
			Passed:  true,
		},
		{
			Name:    "digits",
			Count:   1,
			Minimum: 1,
			Passed:  true,
		},
	}, explanation.Classes)

	assert.Equal(t, []RuleExplanation{
		{
			Rule:   "repeat_run",
			Passed: true,
		},
		{
			Rule:   "repeat_total",
			Passed: true,
		},
		{
			Rule:   "sequences.alphabet",
			Passed: true,
		},
		{
			Rule:   "sequences.keyboard",
			Passed: true,
		},
		{
			Rule:   "dictionary",
			Passed: true,
		},
		{
			Rule:   "context",
			Passed: true,
		},
	}, explanation.Rules)
}

func TestExplainStableRuleOrder(t *testing.T) {
	prepared := checkTestPrepared()

	explanation, err := Explain(context.Background(), prepared, []byte{'a', '1'})

	require.NoError(t, err)
	require.Len(t, explanation.Rules, 6)

	assert.Equal(t, "repeat_run", explanation.Rules[0].Rule)
	assert.Equal(t, "repeat_total", explanation.Rules[1].Rule)
	assert.Equal(t, "sequences.alphabet", explanation.Rules[2].Rule)
	assert.Equal(t, "sequences.keyboard", explanation.Rules[3].Rule)
	assert.Equal(t, "dictionary", explanation.Rules[4].Rule)
	assert.Equal(t, "context", explanation.Rules[5].Rule)
}

func TestExplainMultipleRuleViolations(t *testing.T) {
	classMinimums := map[string]int{
		"lower": 1,
	}

	ruleOptions := rules.Options{
		RepeatRun: 2,
		ContextValues: []string{
			"aaa",
		},
		ContextMinLength: 3,
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
		Rules:         ruleOptions,
		Generate: generate.Options{
			MinLength:     3,
			MaxLength:     3,
			Attempts:      1,
			ClassMinimums: classMinimums,
			Rules:         ruleOptions,
		},
	}

	explanation, err := Explain(context.Background(), prepared, []byte{'a', 'a', 'a'})

	require.NoError(t, err)

	assert.False(t, explanation.Passed)
	assert.True(t, explanation.Length.Passed)
	assert.True(t, explanation.Classes[0].Passed)

	require.Len(t, explanation.Rules, 6)

	assert.False(t, explanation.Rules[0].Passed)
	assert.Equal(t, "repeat_run", explanation.Rules[0].Rule)
	assert.Equal(t, []rules.Violation{
		{
			Rule:   "repeat_run",
			Offset: 0,
			Length: 3,
		},
	}, explanation.Rules[0].Violations)

	assert.True(t, explanation.Rules[1].Passed)
	assert.True(t, explanation.Rules[2].Passed)
	assert.True(t, explanation.Rules[3].Passed)
	assert.True(t, explanation.Rules[4].Passed)

	assert.False(t, explanation.Rules[5].Passed)
	assert.Equal(t, "context", explanation.Rules[5].Rule)
	assert.Equal(t, []rules.Violation{
		{
			Rule:   "context",
			Offset: 0,
			Length: 3,
		},
	}, explanation.Rules[5].Violations)
}

func TestExplainMultipleViolationsOfSameRule(t *testing.T) {
	classMinimums := map[string]int{
		"lower": 1,
	}

	ruleOptions := rules.Options{
		RepeatRun: 2,
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
		Rules:         ruleOptions,
		Generate: generate.Options{
			MinLength:     6,
			MaxLength:     6,
			Attempts:      1,
			ClassMinimums: classMinimums,
			Rules:         ruleOptions,
		},
	}

	explanation, err := Explain(context.Background(), prepared, []byte{'a', 'a', 'a', 'b', 'b', 'b'})

	require.NoError(t, err)
	assert.False(t, explanation.Passed)

	require.Len(t, explanation.Rules, 6)

	repeatRun := explanation.Rules[0]

	assert.Equal(t, "repeat_run", repeatRun.Rule)
	assert.False(t, repeatRun.Passed)

	assert.Equal(t, []rules.Violation{
		{
			Rule:   "repeat_run",
			Offset: 0,
			Length: 3,
		},
		{
			Rule:   "repeat_run",
			Offset: 3,
			Length: 3,
		},
	}, repeatRun.Violations)
}

func TestExplainLengthAndClassViolations(t *testing.T) {
	prepared := checkTestPrepared()

	prepared.Generate.MinLength = 3
	prepared.Generate.MaxLength = 4

	explanation, err := Explain(context.Background(), prepared, []byte{'a', 'b'})

	require.NoError(t, err)

	assert.False(t, explanation.Passed)
	assert.False(t, explanation.Length.Passed)

	require.Len(t, explanation.Classes, 2)

	assert.True(t, explanation.Classes[0].Passed)
	assert.False(t, explanation.Classes[1].Passed)

	for _, ruleExplanation := range explanation.Rules {
		assert.True(t, ruleExplanation.Passed)
		assert.Empty(t, ruleExplanation.Violations)
	}
}

func TestExplainCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	explanation, err := Explain(ctx, checkTestPrepared(), []byte{'a', '1'})

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, Explanation{}, explanation)
}

func TestExplainRulesError(t *testing.T) {
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

	explanation, err := Explain(context.Background(), prepared, []byte{'q', 'w', 'e'})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "explain password")
	assert.ErrorContains(t, err, `unknown keyboard layout "unknown"`)

	assert.Equal(t, Explanation{}, explanation)
}
