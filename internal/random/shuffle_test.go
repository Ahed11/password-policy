package random

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShuffleDeterministic(t *testing.T) {
	values := []rune{'A', 'B', 'C', 'D'}

	source := &controlledSource{
		data: []byte{130, 100, 0},
	}

	err := Shuffle(source, len(values),
		func(i, j int) {
			values[i], values[j] = values[j], values[i]
		},
	)

	assert.NoError(t, err)
	assert.Equal(t, []rune{'D', 'A', 'B', 'C'}, values)
	assert.Equal(t, 3, source.readCalls)
}

func TestShuffleRetriesRejectedRangeValue(t *testing.T) {
	values := []rune{'A', 'B', 'C'}

	source := &controlledSource{
		data: []byte{
			255,
			170,
			0,
		},
	}

	err := Shuffle(source, len(values),
		func(i, j int) {
			values[i], values[j] = values[j], values[i]
		},
	)

	assert.NoError(t, err)
	assert.Equal(t, []rune{'B', 'A', 'C'}, values)
	assert.Equal(t, 3, source.readCalls)
}

func TestShuffleSmallSizesDoNotReadSource(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{
			name: "zero_elements",
			n:    0,
		},
		{
			name: "one_element",
			n:    1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &controlledSource{}
			swapCalls := 0

			err := Shuffle(source, test.n,
				func(i, j int) {
					swapCalls++
				},
			)

			assert.NoError(t, err)
			assert.Equal(t, 0, source.readCalls)
			assert.Equal(t, 0, swapCalls)
		})
	}
}

func TestShuffleSourceError(t *testing.T) {
	source := &controlledSource{}

	err := Shuffle(source, 2,
		func(i, j int) {},
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "shuffle index for position 1")
	assert.ErrorContains(t, err, "random range [0, 2)")
	assert.ErrorContains(t, err, "read random bytes")
	assert.ErrorIs(t, err, io.EOF)
}

func TestShuffleInvalidArguments(t *testing.T) {
	t.Run("negative_size", func(t *testing.T) {
		err := Shuffle(&controlledSource{}, -1, func(i, j int) {})

		assert.ErrorContains(t, err, "shuffle size must be greater than or equal to 0")
	})

	t.Run("nil_source", func(t *testing.T) {
		err := Shuffle(nil, 2, func(i, j int) {})

		assert.ErrorContains(t, err, "random source is nil")
	})

	t.Run("nil_swap", func(t *testing.T) {
		err := Shuffle(&controlledSource{}, 2, nil)

		assert.ErrorContains(t, err, "shuffle swap function is nil")
	})
}