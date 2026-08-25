package rules

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestCheckAlphabetSequence(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		limit    int
		want     []alphabetSequenceViolation
	}{
		{
			name:     "disabled",
			password: []byte{'a', 'b', 'c'},
			limit:    0,
			want:     nil,
		},
		{
			name:     "empty_password",
			password: nil,
			limit:    3,
			want:     nil,
		},
		{
			name:     "no_sequence",
			password: []byte{'a', 'b', 'x', 'c'},
			limit:    3,
			want:     nil,
		},
		{
			name:     "increasing_exactly_at_limit",
			password: []byte{'a', 'b', 'c'},
			limit:    3,
			want: []alphabetSequenceViolation{
				{
					offset: 0,
					length: 3,
				},
			},
		},
		{
			name:     "increasing_longer_than_limit",
			password: []byte{'a', 'b', 'c', 'd'},
			limit:    3,
			want: []alphabetSequenceViolation{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:     "decreasing",
			password: []byte{'d', 'c', 'b', 'a'},
			limit:    3,
			want: []alphabetSequenceViolation{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:     "case_insensitive",
			password: []byte{'a', 'B', 'c'},
			limit:    3,
			want: []alphabetSequenceViolation{
				{
					offset: 0,
					length: 3,
				},
			},
		},
		{
			name:     "sequence_in_middle",
			password: []byte{'x', 'a', 'b', 'c', 'y'},
			limit:    3,
			want: []alphabetSequenceViolation{
				{
					offset: 1,
					length: 3,
				},
			},
		},
		{
			name:     "direction_change",
			password: []byte{'a', 'b', 'c', 'b', 'a'},
			limit:    3,
			want: []alphabetSequenceViolation{
				{
					offset: 0,
					length: 3,
				},
				{
					offset: 2,
					length: 3,
				},
			},
		},
		{
			name:     "multiple_sequences",
			password: []byte{'a', 'b', 'c', 'x', '3', '2', '1'},
			limit:    3,
			want: []alphabetSequenceViolation{
				{
					offset: 0,
					length: 3,
				},
				{
					offset: 4,
					length: 3,
				},
			},
		},
		{
			name:     "limit_one",
			password: []byte{'a', 'x'},
			limit:    1,
			want: []alphabetSequenceViolation{
				{
					offset: 0,
					length: 1,
				},
				{
					offset: 1,
					length: 1,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := checkAlphabetSequence(test.password, test.limit)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestCheckAlphabetSequenceUnicode(t *testing.T) {
	var password []byte

	for _, r := range []rune{'x', 'α', 'β', 'γ', 'y'} {
		password = utf8.AppendRune(password, r)
	}

	got := checkAlphabetSequence(password, 3)

	assert.Equal(t, []alphabetSequenceViolation{
		{
			offset: 1,
			length: 3,
		},
	}, got)
}
