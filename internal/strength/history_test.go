package strength

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequiredHistoryEntropy(t *testing.T) {
	tests := []struct {
		name   string
		window int
		want   float64
	}{
		{
			name:   "disabled",
			window: 0,
			want:   0,
		},
		{
			name:   "window_one",
			window: 1,
			want:   10,
		},
		{
			name:   "window_four",
			window: 4,
			want:   12,
		},
		{
			name:   "window_eight",
			window: 8,
			want:   13,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := RequiredHistoryEntropy(test.window)

			require.NoError(t, err)
			assert.InDelta(t, test.want, got, 1e-12)
		})
	}
}

func TestRequiredHistoryEntropyNegativeWindow(t *testing.T) {
	got, err := RequiredHistoryEntropy(-1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "history window must not be negative")
	assert.Equal(t, 0.0, got)
}

func TestCheckHistoryWindowDisabled(t *testing.T) {
	err := CheckHistoryWindow(math.Inf(-1), 0)

	assert.NoError(t, err)
}

func TestCheckHistoryWindowExactlyAtBoundary(t *testing.T) {
	err := CheckHistoryWindow(12, 4)

	assert.NoError(t, err)
}

func TestCheckHistoryWindowAboveBoundary(t *testing.T) {
	err := CheckHistoryWindow(15.5, 4)

	assert.NoError(t, err)
}

func TestCheckHistoryWindowBelowBoundary(t *testing.T) {
	err := CheckHistoryWindow(11.9, 4)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHistoryWindowTooNarrow)
	assert.ErrorContains(t, err, "policy is too narrow for history window 4")
	assert.ErrorContains(t, err, "lower bound 11.9 bits")
	assert.ErrorContains(t, err, "required at least 12.0")
}

func TestCheckHistoryWindowNegativeInfinity(t *testing.T) {
	err := CheckHistoryWindow(math.Inf(-1), 4)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHistoryWindowTooNarrow)
}

func TestCheckHistoryWindowPositiveInfinity(t *testing.T) {
	err := CheckHistoryWindow(math.Inf(1), 4)

	assert.NoError(t, err)
}

func TestCheckHistoryWindowNaN(t *testing.T) {
	err := CheckHistoryWindow(math.NaN(), 4)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "entropy lower bound must not be NaN")
	assert.NotErrorIs(t, err, ErrHistoryWindowTooNarrow)
}

func TestCheckHistoryWindowNegativeWindow(t *testing.T) {
	err := CheckHistoryWindow(20, -1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "history window must not be negative")
	assert.NotErrorIs(t, err, ErrHistoryWindowTooNarrow)
}
