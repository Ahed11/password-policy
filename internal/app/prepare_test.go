package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepare(t *testing.T) {
	cfg := prepareTestConfig()

	contextValues := []string{
		"svc-01",
		"example",
	}

	prepared, err := Prepare(
		context.Background(),
		cfg,
		PrepareOptions{
			ContextValues: contextValues,
		},
	)

	require.NoError(t, err)

	assert.Equal(t, cfg, prepared.Config)

	assert.Len(t, prepared.Alphabet.Classes, 2)
	assert.ElementsMatch(t, []rune{'a', 'b', '1', '2'}, prepared.Alphabet.Union)

	assert.Equal(t, map[string]int{
		"lower":  2,
		"digits": 2,
	}, prepared.ClassMinimums)

	assert.Equal(t, 4, prepared.Generate.MinLength)
	assert.Equal(t, 6, prepared.Generate.MaxLength)
	assert.Equal(t, 10, prepared.Generate.Attempts)

	assert.Equal(t, 2, prepared.Rules.RepeatRun)
	assert.True(t, prepared.Rules.RepeatTotal)

	assert.Equal(t, 3, prepared.Rules.AlphabetSequence)

	assert.Equal(t, 3, prepared.Rules.KeyboardSequence)

	assert.Equal(t, []string{"qwerty"}, prepared.Rules.KeyboardLayouts)

	assert.Equal(t, []string{"svc-01", "example"}, prepared.Rules.ContextValues)

	assert.Equal(t, 3, prepared.Rules.ContextMinLength)

	assert.True(t, prepared.Rules.ContextCaseInsensitive)

	assert.True(t, prepared.Rules.ContextLeet)

	assert.Nil(t, prepared.Rules.Dictionary)

	assert.Equal(t, prepared.ClassMinimums, prepared.Generate.ClassMinimums)

	assert.Equal(t, prepared.Rules, prepared.Generate.Rules)
}

func TestPrepareCopiesContextValues(t *testing.T) {
	cfg := prepareTestConfig()

	values := []string{
		"svc-01",
		"example",
	}

	prepared, err := Prepare(
		context.Background(),
		cfg,
		PrepareOptions{
			ContextValues: values,
		},
	)
	require.NoError(t, err)

	values[0] = "changed"

	assert.Equal(t, []string{"svc-01", "example"}, prepared.Rules.ContextValues)
}

func TestPrepareLoadsDictionary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary.txt")

	err := os.WriteFile(path, []byte("admin\nroot\n"), 0600)
	require.NoError(t, err)

	cfg := prepareTestConfig()

	cfg.Policy.Forbid.Dictionary.Path = path
	cfg.Policy.Forbid.Dictionary.MinLength = 4
	cfg.Policy.Forbid.Dictionary.CaseInsensitive = true
	cfg.Policy.Forbid.Dictionary.Leet = true

	prepared, err := Prepare(context.Background(), cfg, PrepareOptions{})

	require.NoError(t, err)
	require.NotNil(t, prepared.Rules.Dictionary)

	matches := prepared.Rules.Dictionary.Find([]byte{'X', '4', 'd', 'm', 'i', 'n', '!'})

	require.Len(t, matches, 1)

	assert.Equal(t, 1, matches[0].Offset)
	assert.Equal(t, 5, matches[0].Length)
}

func TestPrepareDictionaryError(t *testing.T) {
	cfg := prepareTestConfig()

	cfg.Policy.Forbid.Dictionary.Path = filepath.Join(t.TempDir(), "missing.txt")

	cfg.Policy.Forbid.Dictionary.MinLength = 4

	prepared, err := Prepare(context.Background(), cfg, PrepareOptions{})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "prepare dictionary")

	assert.Equal(t, Prepared{}, prepared)
}

func TestPrepareCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prepared, err := Prepare(ctx, prepareTestConfig(), PrepareOptions{})

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, Prepared{}, prepared)
}

func TestPrepareLoadsCustomKeyboardLayout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-layout.txt")

	err := os.WriteFile(path, []byte("12345\nabcde\n"), 0o600)
	require.NoError(t, err)

	cfg := prepareTestConfig()

	cfg.Policy.Forbid.Sequences.Alphabet = 0

	cfg.Policy.Forbid.Sequences.Layouts = []string{path}

	prepared, err := Prepare(context.Background(), cfg, PrepareOptions{})
	require.NoError(t, err)

	assert.Equal(
		t,
		[][]rune{
			[]rune("12345"),
			[]rune("abcde"),
		},
		prepared.Rules.KeyboardLayoutTables[path],
	)

	violations, err := rules.Check([]byte("123"), prepared.Rules)
	require.NoError(t, err)

	require.Len(t, violations, 1)

	assert.Equal(t, "sequences.keyboard", violations[0].Rule)
	assert.Equal(t, 0, violations[0].Offset)
	assert.Equal(t, 3, violations[0].Length)
	assert.Equal(t, path, violations[0].Layout)
}

func TestPrepareCustomKeyboardLayoutError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-layout.txt")

	cfg := prepareTestConfig()

	cfg.Policy.Forbid.Sequences.Layouts = []string{path}

	prepared, err := Prepare(context.Background(), cfg, PrepareOptions{})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "prepare keyboard layouts")
	assert.ErrorContains(t, err, "missing-layout.txt")

	assert.Equal(t, Prepared{}, prepared)
}

func prepareTestConfig() policy.Config {
	var cfg policy.Config

	cfg.Policy.Length.Min = 4
	cfg.Policy.Length.Max = 6
	cfg.Policy.Attempts = 10

	cfg.Policy.Classes = []policy.Class{
		{
			Name:     "lower",
			Alphabet: "ab",
			Min:      2,
		},
		{
			Name:     "digits",
			Alphabet: "12",
			Min:      2,
		},
	}

	cfg.Policy.Forbid.RepeatRun = 2
	cfg.Policy.Forbid.RepeatTotal = true

	cfg.Policy.Forbid.Sequences.Alphabet = 3
	cfg.Policy.Forbid.Sequences.Keyboard = 3
	cfg.Policy.Forbid.Sequences.Layouts = []string{"qwerty"}

	cfg.Policy.Forbid.Dictionary.CaseInsensitive = true
	cfg.Policy.Forbid.Dictionary.Leet = true

	cfg.Policy.Forbid.Context.MinLength = 3

	return cfg
}
