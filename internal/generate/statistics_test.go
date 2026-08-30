package generate

import (
	"bytes"
	cryptorand "crypto/rand"
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/secret"
)

const chiSquareAlpha = 1e-10

func TestGeneratedCharacterDistributionChiSquare(t *testing.T) {
	const (
		sampleCount  = 250_000
		passwordLen  = 4
		alphabetSize = 10
		critical     = 65.82 // df=9, alpha=1e-10
	)

	source := bytes.NewReader(
		statisticalRandomBytes(t, 8<<20),
	)

	buildResult := alphabet.BuildResult{
		Union: []rune("0123456789"),
	}

	options := Options{
		MinLength: passwordLen,
		MaxLength: passwordLen,
		Attempts:  1,
	}

	counts := make([][]int, passwordLen)

	for position := range counts {
		counts[position] = make(
			[]int,
			alphabetSize,
		)
	}

	for sample := 0; sample < sampleCount; sample++ {
		result, err := Generate(
			source,
			buildResult,
			options,
		)
		if err != nil {
			t.Fatalf(
				"generate sample %d: %v",
				sample,
				err,
			)
		}

		if len(result.Password) != passwordLen {
			secret.Zero(result.Password)

			t.Fatalf(
				"generated password length = %d, want %d",
				len(result.Password),
				passwordLen,
			)
		}

		for position, symbol := range result.Password {
			index := int(symbol - '0')

			if index < 0 ||
				index >= alphabetSize {

				secret.Zero(
					result.Password,
				)

				t.Fatalf(
					"generated unexpected symbol %q at position %d",
					symbol,
					position,
				)
			}

			counts[position][index]++
		}

		secret.Zero(result.Password)
	}

	expected := float64(sampleCount) /
		alphabetSize

	for position, observed := range counts {
		statistic := chiSquareStatistic(
			observed,
			expected,
		)

		if statistic >= critical {
			t.Fatalf(
				"position %d chi-square = %.4f, want < %.2f (alpha %.0e)",
				position,
				statistic,
				critical,
				chiSquareAlpha,
			)
		}
	}
}

func TestChooseLengthDistributionChiSquare(t *testing.T) {
	const (
		sampleCount = 1_200_000
		minLength   = 12
		maxLength   = 16
		lengthCount = maxLength - minLength + 1
		critical    = 52.68 // df=4, alpha=1e-10
	)

	source := bytes.NewReader(
		statisticalRandomBytes(t, 2<<20),
	)

	counts := make(
		[]int,
		lengthCount,
	)

	for sample := 0; sample < sampleCount; sample++ {
		length, err := chooseLength(
			source,
			minLength,
			maxLength,
		)
		if err != nil {
			t.Fatalf(
				"choose length on sample %d: %v",
				sample,
				err,
			)
		}

		counts[length-minLength]++
	}

	expected := float64(sampleCount) /
		lengthCount

	statistic := chiSquareStatistic(
		counts,
		expected,
	)

	if statistic >= critical {
		t.Fatalf(
			"length chi-square = %.4f, want < %.2f (alpha %.0e); counts=%v",
			statistic,
			critical,
			chiSquareAlpha,
			counts,
		)
	}
}

func chiSquareStatistic(
	observed []int,
	expected float64,
) float64 {
	var statistic float64

	for _, count := range observed {
		difference :=
			float64(count) - expected

		statistic +=
			difference *
				difference /
				expected
	}

	return statistic
}

func statisticalRandomBytes(
	t *testing.T,
	size int,
) []byte {
	t.Helper()

	data := make([]byte, size)

	if _, err := cryptorand.Read(data); err != nil {
		t.Fatalf(
			"read statistical random bytes: %v",
			err,
		)
	}

	return data
}
