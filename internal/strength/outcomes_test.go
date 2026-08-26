package strength

import (
	"math/big"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCountOutcomesSingleClassWithRepeats(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	got, err := countOutcomes(
		buildResult,
		1,
		2,
		map[string]int{
			"letters": 1,
		},
		false,
	)

	require.NoError(t, err)
	assertBigIntEqual(t, 6, got)
}

func TestCountOutcomesSingleClassWithoutRepeats(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	got, err := countOutcomes(
		buildResult,
		1,
		2,
		map[string]int{
			"letters": 1,
		},
		true,
	)

	require.NoError(t, err)
	assertBigIntEqual(t, 4, got)
}

func TestCountOutcomesTwoClassesFixedLength(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
			{
				Name:     "digits",
				Alphabet: []rune{'0', '1'},
			},
		},
		Union: []rune{'a', 'b', '0', '1'},
	}

	got, err := countOutcomes(
		buildResult,
		2,
		2,
		map[string]int{
			"letters": 1,
			"digits":  1,
		},
		false,
	)

	require.NoError(t, err)
	assertBigIntEqual(t, 8, got)
}

func TestCountOutcomesExtraCharactersWithRepeats(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
			{
				Name:     "digits",
				Alphabet: []rune{'0', '1'},
			},
		},
		Union: []rune{'a', 'b', '0', '1'},
	}

	got, err := countOutcomes(
		buildResult,
		3,
		3,
		map[string]int{
			"letters": 1,
			"digits":  1,
		},
		false,
	)

	require.NoError(t, err)
	assertBigIntEqual(t, 48, got)
}

func TestCountOutcomesExtraCharactersWithoutRepeats(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
			{
				Name:     "digits",
				Alphabet: []rune{'0', '1'},
			},
		},
		Union: []rune{'a', 'b', '0', '1'},
	}

	got, err := countOutcomes(
		buildResult,
		3,
		3,
		map[string]int{
			"letters": 1,
			"digits":  1,
		},
		true,
	)

	require.NoError(t, err)
	assertBigIntEqual(t, 24, got)
}

func TestCountOutcomesImpossibleWithoutRepeats(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	got, err := countOutcomes(
		buildResult,
		3,
		3,
		map[string]int{
			"letters": 1,
		},
		true,
	)

	require.NoError(t, err)
	assertBigIntEqual(t, 0, got)
}

func TestCountOutcomesMissingClassMinimum(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	got, err := countOutcomes(
		buildResult,
		1,
		2,
		map[string]int{},
		false,
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, `missing minimum for class "letters"`)
	assert.Nil(t, got)
}

func TestCountOutcomesInvalidLengthRange(t *testing.T) {
	tests := []struct {
		name        string
		minLength   int
		maxLength   int
		errContains string
	}{
		{
			name:        "minimum_is_zero",
			minLength:   0,
			maxLength:   2,
			errContains: "minimum length must be greater than zero",
		},
		{
			name:        "maximum_less_than_minimum",
			minLength:   3,
			maxLength:   2,
			errContains: "maximum length 2 is less than minimum length 3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := countOutcomes(
				alphabet.BuildResult{},
				test.minLength,
				test.maxLength,
				nil,
				false,
			)

			assert.Error(t, err)
			assert.ErrorContains(t, err, test.errContains)
			assert.Nil(t, got)
		})
	}
}

func TestCountOutcomesNegativeClassMinimum(t *testing.T) {
	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	got, err := countOutcomes(
		buildResult,
		1,
		2,
		map[string]int{
			"letters": -1,
		},
		false,
	)

	assert.Error(t, err)
	assert.ErrorContains(
		t,
		err,
		`minimum for class "letters" must not be negative`,
	)
	assert.Nil(t, got)
}

func TestCountClassWays(t *testing.T) {
	tests := []struct {
		name         string
		alphabetSize int
		count        int
		repeatTotal  bool
		want         int64
	}{
		{
			name:         "with_repeats",
			alphabetSize: 3,
			count:        2,
			repeatTotal:  false,
			want:         9,
		},
		{
			name:         "without_repeats",
			alphabetSize: 3,
			count:        2,
			repeatTotal:  true,
			want:         6,
		},
		{
			name:         "zero_count_with_repeats",
			alphabetSize: 3,
			count:        0,
			repeatTotal:  false,
			want:         1,
		},
		{
			name:         "zero_count_without_repeats",
			alphabetSize: 3,
			count:        0,
			repeatTotal:  true,
			want:         1,
		},
		{
			name:         "too_many_without_repeats",
			alphabetSize: 3,
			count:        4,
			repeatTotal:  true,
			want:         0,
		},
		{
			name:         "negative_count",
			alphabetSize: 3,
			count:        -1,
			repeatTotal:  false,
			want:         0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := countClassWays(
				test.alphabetSize,
				test.count,
				test.repeatTotal,
			)

			assertBigIntEqual(t, test.want, got)
		})
	}
}

func assertBigIntEqual(
	t *testing.T,
	want int64,
	got *big.Int,
) {
	t.Helper()

	require.NotNil(t, got)

	expected := big.NewInt(want)

	assert.Zero(
		t,
		got.Cmp(expected),
		"expected %s, got %s",
		expected.String(),
		got.String(),
	)
}
