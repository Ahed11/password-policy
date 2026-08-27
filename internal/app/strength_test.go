package app

import (
	"bytes"
	"context"
	"io"
	"math/big"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/strength"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateStrength(t *testing.T) {
	prepared := strengthTestPrepared(0)

	source := bytes.NewReader(bytes.Repeat([]byte{0, 128}, 5000))

	estimate, err := EvaluateStrength(context.Background(), source, prepared)

	require.NoError(t, err)

	assert.InDelta(t, 1.0, estimate.Bits, 1e-12)
	assert.Equal(t, 10_000, estimate.Samples)
	assert.Equal(t, 0, estimate.Rejected)
	assert.Equal(t, 0.0, estimate.RejectionRate)

	require.NotNil(t, estimate.Outcomes)
	assert.Zero(t, estimate.Outcomes.Cmp(big.NewInt(2)))
}

func TestEvaluateStrengthHistoryWindowTooNarrow(t *testing.T) {
	prepared := strengthTestPrepared(1)

	source := bytes.NewReader(bytes.Repeat([]byte{0, 128}, 5000))

	estimate, err := EvaluateStrength(context.Background(), source, prepared)

	assert.Error(t, err)
	assert.ErrorIs(t, err, strength.ErrHistoryWindowTooNarrow)
	assert.ErrorContains(t, err, "check history window solvability")

	assert.InDelta(t, 1.0, estimate.Bits, 1e-12)

	require.NotNil(t, estimate.Outcomes)
	assert.Zero(t, estimate.Outcomes.Cmp(big.NewInt(2)))
}

func TestEvaluateStrengthCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	estimate, err := EvaluateStrength(ctx, bytes.NewReader(nil), strengthTestPrepared(0))

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, strength.Estimate{}, estimate)
}

func TestEvaluateStrengthNilSource(t *testing.T) {
	estimate, err := EvaluateStrength(context.Background(), nil, strengthTestPrepared(0))

	assert.Error(t, err)
	assert.ErrorContains(t, err, "random source must not be nil")

	assert.Equal(t, strength.Estimate{}, estimate)
}

func TestEvaluateStrengthSourceError(t *testing.T) {
	estimate, err := EvaluateStrength(context.Background(), bytes.NewReader(nil), strengthTestPrepared(0))

	assert.Error(t, err)
	assert.ErrorContains(t, err, "evaluate policy strength")
	assert.ErrorIs(t, err, io.EOF)

	assert.Equal(t, strength.Estimate{}, estimate)
}

func TestEvaluateStrengthInvalidHistoryWindow(t *testing.T) {
	prepared := strengthTestPrepared(-1)

	source := bytes.NewReader(bytes.Repeat([]byte{0, 128}, 5000))

	estimate, err := EvaluateStrength(context.Background(), source, prepared)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "history window must not be negative")

	assert.InDelta(t, 1.0, estimate.Bits, 1e-12)
}

func strengthTestPrepared(window int) Prepared {
	classMinimums := map[string]int{
		"letters": 1,
	}

	ruleOptions := rules.Options{}

	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	var cfg policy.Config
	cfg.Issue.History.Window = window

	return Prepared{
		Config:        cfg,
		Alphabet:      buildResult,
		ClassMinimums: classMinimums,
		Rules:         ruleOptions,
		Generate: generate.Options{
			MinLength:     1,
			MaxLength:     1,
			Attempts:      1,
			ClassMinimums: classMinimums,
			Rules:         ruleOptions,
		},
	}
}
