package random

import (
	"fmt"
	"io"
	"math/bits"
)

func bytesNeededForRange(n int) int {
	if n <= 1 {
		return 1
	}

	bitCount := bits.Len64(uint64(n - 1))

	return (bitCount + 7) / 8
}

func rangeParameters(n int, byteCount int) (uint64, uint64) {
	divisor := uint64(n)

	if byteCount < 8 {
		space := uint64(1) << (8 * byteCount)

		bucketSize := space / divisor
		usableLimit := bucketSize * divisor
		maxAccepted := usableLimit - 1

		return bucketSize, maxAccepted
	}

	bucketSize, remainder := bits.Div64(1, 0, divisor)

	if remainder == 0 {
		return bucketSize, ^uint64(0)
	}

	usableLimit := bucketSize * divisor
	maxAccepted := usableLimit - 1

	return bucketSize, maxAccepted
}

func readRandomValue(source Source, byteCount int) (uint64, error) {
	buffer := make([]byte, byteCount)

	if _, err := io.ReadFull(source, buffer); err != nil {
		return 0, fmt.Errorf("read random bytes: %w", err)
	}

	var value uint64

	for _, b := range buffer {
		value = (value << 8) | uint64(b)
	}

	return value, nil
}

// Range возвращает равномерно распределённое случайное значение из диапазона [0, n) без modulo bias.
func Range(source Source, n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("random range size must be greater than 0")
	}

	if n == 1 {
		return 0, nil
	}

	if source == nil {
		return 0, fmt.Errorf("random source is nil")
	}

	byteCount := bytesNeededForRange(n)

	bucketSize, maxAccepted := rangeParameters(n, byteCount)

	for {
		randomValue, err := readRandomValue(source, byteCount)
		if err != nil {
			return 0, fmt.Errorf("random range [0, %d): %w", n, err)
		}

		if randomValue > maxAccepted {
			continue
		}

		index := randomValue / bucketSize

		return int(index), nil
	}
}
