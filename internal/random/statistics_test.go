package random

import (
	"bytes"
	cryptorand "crypto/rand"
	"testing"
)

func TestShufflePositionDistributionChiSquare(t *testing.T) {
	const (
		sampleCount = 250_000
		itemCount   = 8
		critical    = 60.90 // df=7, alpha=1e-10
	)

	source := bytes.NewReader(
		statisticalRandomBytes(t, 8<<20),
	)

	counts := make(
		[][]int,
		itemCount,
	)

	for originalPosition := range counts {
		counts[originalPosition] = make(
			[]int,
			itemCount,
		)
	}

	for sample := 0; sample < sampleCount; sample++ {
		values := [itemCount]int{
			0, 1, 2, 3,
			4, 5, 6, 7,
		}

		err := Shuffle(
			source,
			len(values),
			func(i, j int) {
				values[i], values[j] =
					values[j], values[i]
			},
		)
		if err != nil {
			t.Fatalf(
				"shuffle sample %d: %v",
				sample,
				err,
			)
		}

		for finalPosition, originalPosition := range values {

			counts[originalPosition][finalPosition]++
		}
	}

	expected := float64(sampleCount) /
		itemCount

	for originalPosition, observed := range counts {

		statistic := chiSquareStatistic(
			observed,
			expected,
		)

		if statistic >= critical {
			t.Fatalf(
				"original position %d chi-square = %.4f, want < %.2f (alpha 1e-10); counts=%v",
				originalPosition,
				statistic,
				critical,
				observed,
			)
		}
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
