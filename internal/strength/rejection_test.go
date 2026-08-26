package strength

import (
	"bytes"
	"io"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEstimateRejectionRateNoRejections(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	source := bytes.NewReader([]byte{0, 128, 0, 128})

	got, err := estimateRejectionRateWithSamples(
		source,
		buildResult,
		generate.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			Rules:     rules.Options{},
		},
		4,
	)

	require.NoError(t, err)

	assert.Equal(t, 4, got.samples)
	assert.Equal(t, 0, got.rejected)
	assert.Equal(t, 0.0, got.rate)
}

func TestEstimateRejectionRatePartialRejections(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	source := bytes.NewReader([]byte{0, 128, 0, 128})

	got, err := estimateRejectionRateWithSamples(
		source,
		buildResult,
		generate.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			Rules: rules.Options{
				ContextValues:    []string{"a"},
				ContextMinLength: 1,
			},
		},
		4,
	)

	require.NoError(t, err)

	assert.Equal(t, 4, got.samples)
	assert.Equal(t, 2, got.rejected)
	assert.Equal(t, 0.5, got.rate)
}

func TestEstimateRejectionRateAllRejected(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	source := bytes.NewReader([]byte{0, 0, 0, 0})

	got, err := estimateRejectionRateWithSamples(
		source,
		buildResult,
		generate.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			Rules: rules.Options{
				ContextValues:    []string{"a"},
				ContextMinLength: 1,
			},
		},
		4,
	)

	require.NoError(t, err)

	assert.Equal(t, 4, got.samples)
	assert.Equal(t, 4, got.rejected)
	assert.Equal(t, 1.0, got.rate)
}

func TestEstimateRejectionRateInvalidSampleCount(t *testing.T) {
	tests := []struct {
		name        string
		sampleCount int
	}{
		{
			name:        "zero",
			sampleCount: 0,
		},
		{
			name:        "negative",
			sampleCount: -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := estimateRejectionRateWithSamples(bytes.NewReader(nil), alphabet.BuildResult{}, generate.Options{}, test.sampleCount)

			assert.Error(t, err)
			assert.ErrorContains(t, err, "sample count must be greater than zero")

			assert.Equal(t, rejectionEstimate{}, got)
		})
	}
}

func TestEstimateRejectionRateSourceError(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a', 'b'},
	}

	got, err := estimateRejectionRateWithSamples(
		bytes.NewReader(nil),
		buildResult,
		generate.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			Rules:     rules.Options{},
		},
		2,
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "estimate rejection rate sample 1 of 2")
	assert.ErrorIs(t, err, io.EOF)

	assert.Equal(t, rejectionEstimate{}, got)
}

func TestEstimateRejectionRateRulesError(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Union: []rune{'a'},
	}

	got, err := estimateRejectionRateWithSamples(
		bytes.NewReader(nil),
		buildResult,
		generate.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			Rules: rules.Options{
				KeyboardSequence: 1,
				KeyboardLayouts: []string{
					"unknown",
				},
			},
		},
		1,
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "estimate rejection rate sample 1 of 1: check rules")
	assert.ErrorContains(t, err, `unknown keyboard layout "unknown"`)

	assert.Equal(t, rejectionEstimate{}, got)
}
