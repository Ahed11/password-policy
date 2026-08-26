package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ahed11/password-policy/internal/dictionary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckNoViolations(t *testing.T) {
	violations, err := Check([]byte{'x', '7', '!'}, Options{})

	require.NoError(t, err)
	assert.Nil(t, violations)
}

func TestCheckRepeatTotalViolation(t *testing.T) {
	violations, err := Check([]byte{'a', 'b', 'a'},
		Options{
			RepeatTotal: true,
		},
	)

	require.NoError(t, err)

	assert.Equal(t, []Violation{
		{
			Rule:   "repeat_total",
			Offset: 2,
			Length: 1,
		},
	}, violations)
}

func TestCheckStableViolationOrder(t *testing.T) {
	matcher := loadRulesTestDictionary(t, "admin\n")

	password := []byte{
		'a', 'a', 'a', '#',
		'a', 'b', 'c', '#',
		'q', 'w', 'e', '#',
		'a', 'd', 'm', 'i', 'n', '#',
		'r', 'e', 's',
	}

	violations, err := Check(password,
		Options{
			RepeatRun:        2,
			AlphabetSequence: 3,
			KeyboardSequence: 3,
			KeyboardLayouts:  []string{"qwerty"},
			Dictionary:       matcher,

			ContextValues:    []string{"service"},
			ContextMinLength: 3,
		},
	)

	require.NoError(t, err)

	assert.Equal(t, []Violation{
		{
			Rule:   "repeat_run",
			Offset: 0,
			Length: 3,
		},
		{
			Rule:   "sequences.alphabet",
			Offset: 4,
			Length: 3,
		},
		{
			Rule:   "sequences.keyboard",
			Offset: 8,
			Length: 3,
			Layout: "qwerty",
		},
		{
			Rule:   "dictionary",
			Offset: 12,
			Length: 5,
		},
		{
			Rule:   "context",
			Offset: 18,
			Length: 3,
		},
	}, violations)
}

func TestCheckUnknownKeyboardLayout(t *testing.T) {
	violations, err := Check([]byte{'q', 'w', 'e'},
		Options{
			KeyboardSequence: 3,
			KeyboardLayouts: []string{
				"unknown",
			},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, `unknown keyboard layout "unknown"`)
	assert.Nil(t, violations)
}

func loadRulesTestDictionary(t *testing.T, content string) *dictionary.Matcher {
	t.Helper()

	path := filepath.Join(t.TempDir(), "dictionary.txt")

	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)

	matcher, err := dictionary.Load(path, 1, false, false)
	require.NoError(t, err)

	return matcher
}
