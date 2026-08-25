package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeLeetRune(t *testing.T) {
	tests := []struct {
		name string
		in   rune
		want rune
	}{
		{
			name: "four_to_a",
			in:   '4',
			want: 'a',
		},
		{
			name: "three_to_e",
			in:   '3',
			want: 'e',
		},
		{
			name: "one_to_l",
			in:   '1',
			want: 'l',
		},
		{
			name: "zero_to_o",
			in:   '0',
			want: 'o',
		},
		{
			name: "five_to_s",
			in:   '5',
			want: 's',
		},
		{
			name: "dollar_to_s",
			in:   '$',
			want: 's',
		},
		{
			name: "at_to_a",
			in:   '@',
			want: 'a',
		},
		{
			name: "seven_to_t",
			in:   '7',
			want: 't',
		},
		{
			name: "ordinary_ascii_is_unchanged",
			in:   'x',
			want: 'x',
		},
		{
			name: "unicode_is_unchanged",
			in:   'Ж',
			want: 'Ж',
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeLeetRune(test.in)

			assert.Equal(t, test.want, got)
		})
	}
}
