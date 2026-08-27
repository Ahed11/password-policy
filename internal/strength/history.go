package strength

import (
	"errors"
	"fmt"
	"math"
)

var ErrHistoryWindowTooNarrow = errors.New("policy is too narrow for history window")

func RequiredHistoryEntropy(window int) (float64, error) {
	if window < 0 {
		return 0, fmt.Errorf("history window must not be negative, got %d", window)
	}

	if window == 0 {
		return 0, nil
	}

	return math.Log2(float64(window)) + 10, nil
}

func CheckHistoryWindow(bits float64, window int) error {
	required, err := RequiredHistoryEntropy(window)
	if err != nil {
		return err
	}

	if window == 0 {
		return nil
	}

	if math.IsNaN(bits) {
		return fmt.Errorf("entropy lower bound must not be NaN")
	}

	if bits < required {
		return fmt.Errorf("%w %d: lower bound %.1f bits, required at least %.1f", ErrHistoryWindowTooNarrow, window, bits, required)
	}

	return nil
}
