package random

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

type controlledSource struct {
	data      []byte
	offset    int
	maxChunk  int
	readCalls int
}

func (s *controlledSource) Read(p []byte) (int, error) {
	s.readCalls++

	if s.offset >= len(s.data) {
		return 0, io.EOF
	}

	if s.maxChunk > 0 && len(p) > s.maxChunk {
		p = p[:s.maxChunk]
	}

	n := copy(p, s.data[s.offset:])
	s.offset += n

	return n, nil
}

func TestBytesNeededForRange(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want int
	}{
		{
			name: "one_value",
			n:    1,
			want: 1,
		},
		{
			name: "two_values",
			n:    2,
			want: 1,
		},
		{
			name: "ten_values",
			n:    10,
			want: 1,
		},
		{
			name: "255_values",
			n:    255,
			want: 1,
		},
		{
			name: "256_values",
			n:    256,
			want: 1,
		},
		{
			name: "257_values",
			n:    257,
			want: 2,
		},
		{
			name: "1000_values",
			n:    1000,
			want: 2,
		},
		{
			name: "65536_values",
			n:    65536,
			want: 2,
		},
		{
			name: "65537_values",
			n:    65537,
			want: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := bytesNeededForRange(test.n)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestRangeParameters(t *testing.T) {
	tests := []struct {
		name            string
		n               int
		byteCount       int
		wantBucketSize  uint64
		wantMaxAccepted uint64
	}{
		{
			name:            "ten_values_one_byte",
			n:               10,
			byteCount:       1,
			wantBucketSize:  25,
			wantMaxAccepted: 249,
		},
		{
			name:            "exact_division_one_byte",
			n:               16,
			byteCount:       1,
			wantBucketSize:  16,
			wantMaxAccepted: 255,
		},
		{
			name:            "large_rejected_tail_one_byte",
			n:               200,
			byteCount:       1,
			wantBucketSize:  1,
			wantMaxAccepted: 199,
		},
		{
			name:            "two_bytes",
			n:               300,
			byteCount:       2,
			wantBucketSize:  218,
			wantMaxAccepted: 65399,
		},
		{
			name:            "eight_bytes_exact_division",
			n:               2,
			byteCount:       8,
			wantBucketSize:  uint64(1) << 63,
			wantMaxAccepted: ^uint64(0),
		},
		{
			name:            "eight_bytes_with_remainder",
			n:               3,
			byteCount:       8,
			wantBucketSize:  6148914691236517205,
			wantMaxAccepted: 18446744073709551614,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotBucketSize, gotMaxAccepted := rangeParameters(test.n, test.byteCount)

			assert.Equal(t, test.wantBucketSize, gotBucketSize)
			assert.Equal(t, test.wantMaxAccepted, gotMaxAccepted)
		})
	}
}

func TestReadRandomValue(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		byteCount     int
		maxChunk      int
		want          uint64
		wantReadCalls int
	}{
		{
			name:          "one_byte",
			data:          []byte{42},
			byteCount:     1,
			want:          42,
			wantReadCalls: 1,
		},
		{
			name:          "two_bytes",
			data:          []byte{1, 2},
			byteCount:     2,
			want:          258,
			wantReadCalls: 1,
		},
		{
			name:          "maximum_two_byte_value",
			data:          []byte{255, 255},
			byteCount:     2,
			want:          65535,
			wantReadCalls: 1,
		},
		{
			name:          "short_reads_are_combined",
			data:          []byte{1, 2},
			byteCount:     2,
			maxChunk:      1,
			want:          258,
			wantReadCalls: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &controlledSource{
				data:     test.data,
				maxChunk: test.maxChunk,
			}

			got, err := readRandomValue(source, test.byteCount)

			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantReadCalls, source.readCalls)
		})
	}
}

func TestReadRandomValueNotEnoughBytes(t *testing.T) {
	source := &controlledSource{
		data: []byte{1},
	}

	_, err := readRandomValue(source, 2)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "read random bytes")
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestRange(t *testing.T) {
	tests := []struct {
		name          string
		n             int
		data          []byte
		want          int
		wantReadCalls int
	}{
		{
			name:          "single_value_does_not_read_source",
			n:             1,
			data:          []byte{},
			want:          0,
			wantReadCalls: 0,
		},
		{
			name:          "accepted_value",
			n:             10,
			data:          []byte{42},
			want:          1,
			wantReadCalls: 1,
		},
		{
			name:          "rejected_value_is_retried",
			n:             10,
			data:          []byte{252, 73},
			want:          2,
			wantReadCalls: 2,
		},
		{
			name:          "last_accepted_value",
			n:             10,
			data:          []byte{249},
			want:          9,
			wantReadCalls: 1,
		},
		{
			name:          "first_rejected_value_is_retried",
			n:             10,
			data:          []byte{250, 0},
			want:          0,
			wantReadCalls: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &controlledSource{
				data: test.data,
			}

			got, err := Range(source, test.n)

			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantReadCalls, source.readCalls)
		})
	}
}

func TestRangeInvalidSize(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{
			name: "zero",
			n:    0,
		},
		{
			name: "negative",
			n:    -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &controlledSource{}

			_, err := Range(source, test.n)

			assert.Error(t, err)
			assert.ErrorContains(t, err, "random range size must be greater than 0")
			assert.Equal(t, 0, source.readCalls)
		})
	}
}

func TestRangeSourceError(t *testing.T) {
	source := &controlledSource{
		data: []byte{},
	}

	_, err := Range(source, 10)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "random range [0, 10)")
	assert.ErrorContains(t, err, "read random bytes")
	assert.ErrorIs(t, err, io.EOF)
}

func TestRangeNilSource(t *testing.T) {
	_, err := Range(nil, 10)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "random source is nil")
}
