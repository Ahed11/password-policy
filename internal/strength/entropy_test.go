package strength

import (
	"bytes"
	"io"
	"math"
	"math/big"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEstimateEntropyNoRejections(t *testing.T) {
	buildResult := entropyTestBuildResult()

	source := bytes.NewReader(bytes.Repeat([]byte{0}, rejectionSampleCount))

	got, err := EstimateEntropy(source, buildResult, entropyTestOptions(rules.Options{}))

	require.NoError(t, err)
	require.NotNil(t, got.Outcomes)

	assert.Zero(t, got.Outcomes.Cmp(big.NewInt(2)))

	assert.InDelta(t, 1.0, got.Bits, 1e-12)
	assert.Equal(t, rejectionSampleCount, got.Samples)
	assert.Equal(t, 0, got.Rejected)
	assert.Equal(t, 0.0, got.RejectionRate)
}

func TestEstimateEntropyPartialRejection(t *testing.T) {
	buildResult := entropyTestBuildResult()

	source := bytes.NewReader(bytes.Repeat([]byte{0, 128}, rejectionSampleCount/2))

	got, err := EstimateEntropy(
		source,
		buildResult,
		entropyTestOptions(
			rules.Options{
				ContextValues:    []string{"a"},
				ContextMinLength: 1,
			},
		),
	)

	require.NoError(t, err)
	require.NotNil(t, got.Outcomes)

	assert.Zero(t, got.Outcomes.Cmp(big.NewInt(2)))

	assert.Equal(t, rejectionSampleCount, got.Samples)

	assert.Equal(t, rejectionSampleCount/2, got.Rejected)

	assert.InDelta(t, 0.5, got.RejectionRate, 1e-12)

	assert.InDelta(t, 0.0, got.Bits, 1e-12)
}

func TestEstimateEntropyAllRejected(t *testing.T) {
	buildResult := entropyTestBuildResult()

	source := bytes.NewReader(bytes.Repeat([]byte{0, 128}, rejectionSampleCount/2))

	got, err := EstimateEntropy(
		source,
		buildResult,
		entropyTestOptions(
			rules.Options{
				ContextValues: []string{
					"a",
					"b",
				},
				ContextMinLength: 1,
			},
		),
	)

	require.NoError(t, err)

	assert.Equal(t, rejectionSampleCount, got.Samples)

	assert.Equal(t, rejectionSampleCount, got.Rejected)

	assert.Equal(t, 1.0, got.RejectionRate)
	assert.True(t, math.IsInf(got.Bits, -1))
}

func TestEstimateEntropyIsReproducible(t *testing.T) {
	buildResult := entropyTestBuildResult()

	data := bytes.Repeat([]byte{0, 128}, rejectionSampleCount/2)

	options := entropyTestOptions(
		rules.Options{
			ContextValues:    []string{"a"},
			ContextMinLength: 1,
		},
	)

	first, err := EstimateEntropy(bytes.NewReader(data), buildResult, options)
	require.NoError(t, err)

	second, err := EstimateEntropy(bytes.NewReader(data), buildResult, options)
	require.NoError(t, err)

	assert.Equal(t, first.Bits, second.Bits)
	assert.Equal(t, first.Samples, second.Samples)
	assert.Equal(t, first.Rejected, second.Rejected)
	assert.Equal(t, first.RejectionRate, second.RejectionRate)

	require.NotNil(t, first.Outcomes)
	require.NotNil(t, second.Outcomes)

	assert.Zero(t, first.Outcomes.Cmp(second.Outcomes))
}

func TestEstimateEntropySourceError(t *testing.T) {
	got, err := EstimateEntropy(bytes.NewReader(nil), entropyTestBuildResult(), entropyTestOptions(rules.Options{}))

	assert.Error(t, err)
	assert.ErrorContains(t, err, "estimate prohibition rejection rate")
	assert.ErrorContains(t, err, "estimate rejection rate sample 1")
	assert.ErrorIs(t, err, io.EOF)

	assert.Equal(t, Estimate{}, got)
}

func TestEstimateEntropyZeroOutcomes(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: nil,
			},
		},
	}

	got, err := EstimateEntropy(
		bytes.NewReader(nil),
		buildResult,
		generate.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  1,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
		},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "password outcome count must be greater than zero")

	assert.Equal(t, Estimate{}, got)
}

func TestLog2BigInt(t *testing.T) {
	tests := []struct {
		name  string
		value *big.Int
		want  float64
	}{
		{
			name:  "one",
			value: big.NewInt(1),
			want:  0,
		},
		{
			name:  "two",
			value: big.NewInt(2),
			want:  1,
		},
		{
			name:  "eight",
			value: big.NewInt(8),
			want:  3,
		},
		{
			name:  "1024",
			value: big.NewInt(1024),
			want:  10,
		},
		{
			name:  "non_power_of_two",
			value: big.NewInt(3),
			want:  math.Log2(3),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := log2BigInt(test.value)

			require.NoError(t, err)

			assert.InDelta(t, test.want, got, 1e-12)
		})
	}
}

func TestLog2BigIntHugeValue(t *testing.T) {
	value := new(big.Int).Lsh(big.NewInt(1), 1000)

	got, err := log2BigInt(value)

	require.NoError(t, err)

	assert.InDelta(t, 1000.0, got, 1e-12)
}

func TestLog2BigIntInvalidValue(t *testing.T) {
	tests := []struct {
		name  string
		value *big.Int
	}{
		{
			name:  "nil",
			value: nil,
		},
		{
			name:  "zero",
			value: big.NewInt(0),
		},
		{
			name:  "negative",
			value: big.NewInt(-1),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := log2BigInt(test.value)

			assert.Error(t, err)
			assert.ErrorContains(t, err, "value must be a positive integer")

			assert.Equal(t, 0.0, got)
		})
	}
}

func entropyTestBuildResult() alphabet.BuildResult {
	return alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}
}

func entropyTestOptions(ruleOptions rules.Options) generate.Options {
	return generate.Options{
		MinLength: 1,
		MaxLength: 1,
		Attempts:  1,
		ClassMinimums: map[string]int{
			"letters": 1,
		},
		Rules: ruleOptions,
	}
}

func TestEstimateEntropyDeterministicIsReproducible(t *testing.T) {
	buildResult := entropyTestBuildResult()

	options := entropyTestOptions(
		rules.Options{
			ContextValues:    []string{"a"},
			ContextMinLength: 1,
		},
	)

	first, err := EstimateEntropyDeterministic(buildResult, options)
	require.NoError(t, err)

	second, err := EstimateEntropyDeterministic(buildResult, options)
	require.NoError(t, err)

	assert.Equal(t, first.Bits, second.Bits)
	assert.Equal(t, first.Samples, second.Samples)
	assert.Equal(t, first.Rejected, second.Rejected)
	assert.Equal(t, first.RejectionRate, second.RejectionRate)

	require.NotNil(t, first.Outcomes)
	require.NotNil(t, second.Outcomes)

	assert.Zero(t, first.Outcomes.Cmp(second.Outcomes))
}
