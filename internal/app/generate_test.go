package app

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	generator "github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	prepared := generateTestPrepared()

	source := bytes.NewReader([]byte{0, 128, 0})

	results, err := Generate(context.Background(), source, prepared, 3)

	require.NoError(t, err)
	require.Len(t, results, 3)

	assert.Equal(t, []byte{'a'}, results[0].Password)
	assert.Equal(t, 1, results[0].Attempts)

	assert.Equal(t, []byte{'b'}, results[1].Password)
	assert.Equal(t, 1, results[1].Attempts)

	assert.Equal(t, []byte{'a'}, results[2].Password)
	assert.Equal(t, 1, results[2].Attempts)

	zeroGenerationResults(results)
}

func TestGenerateInvalidCount(t *testing.T) {
	tests := []struct {
		name  string
		count int
	}{
		{
			name:  "zero",
			count: 0,
		},
		{
			name:  "negative",
			count: -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := Generate(context.Background(), bytes.NewReader(nil), generateTestPrepared(), test.count)

			assert.Error(t, err)
			assert.ErrorContains(t, err, "count must be greater than zero")

			assert.Nil(t, results)
		})
	}
}

func TestGenerateNilSource(t *testing.T) {
	results, err := Generate(context.Background(), nil, generateTestPrepared(), 1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "random source must not be nil")

	assert.Nil(t, results)
}

func TestGenerateCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := Generate(ctx, bytes.NewReader(nil), generateTestPrepared(), 1)

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Nil(t, results)
}

func TestGenerateCancellationAfterPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	source := &cancelingGenerateSource{
		cancel: cancel,
		data:   []byte{0},
	}

	results, err := Generate(ctx, source, generateTestPrepared(), 1)

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Nil(t, results)
}

func TestGenerateSourceError(t *testing.T) {
	source := bytes.NewReader([]byte{0})

	results, err := Generate(context.Background(), source, generateTestPrepared(), 2)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "generate password 2 of 2")
	assert.ErrorIs(t, err, io.EOF)

	assert.Nil(t, results)
}

func TestGeneratePolicyTooStrict(t *testing.T) {
	prepared := Prepared{
		Alphabet: alphabet.BuildResult{
			Union: []rune{'a'},
		},
		Generate: generator.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  2,
			Rules: rules.Options{
				ContextValues:    []string{"a"},
				ContextMinLength: 1,
			},
		},
	}

	results, err := Generate(context.Background(), bytes.NewReader(nil), prepared, 1)

	assert.Error(t, err)
	assert.ErrorIs(t, err, generator.ErrPolicyTooStrict)
	assert.ErrorContains(t, err, "generate password 1 of 1")

	assert.Nil(t, results)
}

func TestZeroGenerationResults(t *testing.T) {
	results := []GenerationResult{
		{
			Password: []byte{1, 2, 3},
			Attempts: 1,
		},
		{
			Password: []byte{4, 5},
			Attempts: 2,
		},
	}

	zeroGenerationResults(results)

	assert.Equal(t, []byte{0, 0, 0}, results[0].Password)

	assert.Equal(t, []byte{0, 0}, results[1].Password)

	assert.Equal(t, 1, results[0].Attempts)
	assert.Equal(t, 2, results[1].Attempts)
}

func generateTestPrepared() Prepared {
	return Prepared{
		Alphabet: alphabet.BuildResult{
			Union: []rune{'a', 'b'},
		},
		Generate: generator.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			Rules:     rules.Options{},
		},
	}
}

type cancelingGenerateSource struct {
	cancel context.CancelFunc
	data   []byte
	used   bool
}

func (s *cancelingGenerateSource) Read(p []byte) (int, error) {
	if s.used {
		return 0, io.EOF
	}

	if len(s.data) == 0 {
		return 0, io.EOF
	}

	n := copy(p, s.data)

	s.used = true
	s.cancel()

	return n, nil
}
