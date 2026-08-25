package rules

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestCheckRepeatTotal(t *testing.T) {
	tests := []struct {
		name        string
		password    []byte
		repeatTotal bool
		want        []repeatTotalViolation
	}{
		{
			name:        "disabled",
			password:    []byte{'a', 'b', 'a'},
			repeatTotal: false,
			want:        nil,
		},
		{
			name:        "empty_password",
			password:    nil,
			repeatTotal: true,
			want:        nil,
		},
		{
			name:        "all_unique",
			password:    []byte{'a', 'b', 'c', '1', '2'},
			repeatTotal: true,
			want:        nil,
		},
		{
			name:        "single_repeat",
			password:    []byte{'a', 'b', 'c', 'a'},
			repeatTotal: true,
			want: []repeatTotalViolation{
				{
					offset: 3,
					length: 1,
				},
			},
		},
		{
			name:        "multiple_different_repeats",
			password:    []byte{'a', 'b', 'c', 'a', 'b'},
			repeatTotal: true,
			want: []repeatTotalViolation{
				{
					offset: 3,
					length: 1,
				},
				{
					offset: 4,
					length: 1,
				},
			},
		},
		{
			name:        "same_rune_repeated_multiple_times",
			password:    []byte{'a', 'b', 'a', 'c', 'a'},
			repeatTotal: true,
			want: []repeatTotalViolation{
				{
					offset: 2,
					length: 1,
				},
				{
					offset: 4,
					length: 1,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := checkRepeatTotal(test.password, test.repeatTotal)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestCheckRepeatTotalUnicode(t *testing.T) {
	var password []byte

	for _, r := range []rune{'a', '😀', 'b', '😀'} {
		password = utf8.AppendRune(password, r)
	}

	got := checkRepeatTotal(password, true)

	assert.Equal(t, []repeatTotalViolation{
		{
			offset: 3,
			length: 1,
		},
	}, got)
}
