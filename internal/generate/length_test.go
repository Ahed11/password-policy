package generate

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

type countingSource struct {
	reader    *bytes.Reader
	readCalls int
}

func newCountingSource(data []byte) *countingSource {
	return &countingSource{
		reader: bytes.NewReader(data),
	}
}

func (s *countingSource) Read(p []byte) (int, error) {
	s.readCalls++
	return s.reader.Read(p)
}

func TestChooseLength(t *testing.T) {
	tests := []struct {
		name          string
		min           int
		max           int
		data          []byte
		want          int
		wantReadCalls int
	}{
		{
			name:          "fixed_length_does_not_read_source",
			min:           12,
			max:           12,
			data:          []byte{},
			want:          12,
			wantReadCalls: 0,
		},
		{
			name:          "lower_bound",
			min:           12,
			max:           16,
			data:          []byte{0},
			want:          12,
			wantReadCalls: 1,
		},
		{
			name:          "middle_value",
			min:           12,
			max:           16,
			data:          []byte{102},
			want:          14,
			wantReadCalls: 1,
		},
		{
			name:          "upper_bound",
			min:           12,
			max:           16,
			data:          []byte{204},
			want:          16,
			wantReadCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(test.data)

			got, err := chooseLength(source, test.min, test.max)

			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantReadCalls, source.readCalls)
		})
	}
}

func TestChooseLengthInvalidBounds(t *testing.T) {
	tests := []struct {
		name        string
		min         int
		max         int
		errContains string
	}{
		{
			name:        "zero_min",
			min:         0,
			max:         10,
			errContains: "length.min must be greater than 0",
		},
		{
			name:        "negative_min",
			min:         -1,
			max:         10,
			errContains: "length.min must be greater than 0",
		},
		{
			name:        "max_less_than_min",
			min:         10,
			max:         9,
			errContains: "length.max must be greater than or equal to length.min",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(nil)

			_, err := chooseLength(source, test.min, test.max)

			assert.Error(t, err)
			assert.ErrorContains(t, err, test.errContains)
			assert.Equal(t, 0, source.readCalls)
		})
	}
}

func TestChooseLengthSourceError(t *testing.T) {
	source := newCountingSource(nil)

	_, err := chooseLength(source, 12, 16)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "choose password length in [12, 16]")
	assert.ErrorIs(t, err, io.EOF)
}
