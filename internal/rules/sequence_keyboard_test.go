package rules

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestCheckKeyboardSequenceQWERTY(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		limit    int
		want     []keyboardSequenceViolation
	}{
		{
			name:     "disabled",
			password: []byte{'q', 'w', 'e'},
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
			password: []byte{'q', 'w', 'x'},
			limit:    3,
			want:     nil,
		},
		{
			name:     "forward_exactly_at_limit",
			password: []byte{'q', 'w', 'e'},
			limit:    3,
			want: []keyboardSequenceViolation{
				{
					offset: 0,
					length: 3,
					layout: "qwerty",
				},
			},
		},
		{
			name:     "backward",
			password: []byte{'e', 'w', 'q'},
			limit:    3,
			want: []keyboardSequenceViolation{
				{
					offset: 0,
					length: 3,
					layout: "qwerty",
				},
			},
		},
		{
			name:     "longer_than_limit",
			password: []byte{'q', 'w', 'e', 'r'},
			limit:    3,
			want: []keyboardSequenceViolation{
				{
					offset: 0,
					length: 4,
					layout: "qwerty",
				},
			},
		},
		{
			name:     "second_row",
			password: []byte{'a', 's', 'd', 'f'},
			limit:    3,
			want: []keyboardSequenceViolation{
				{
					offset: 0,
					length: 4,
					layout: "qwerty",
				},
			},
		},
		{
			name:     "does_not_cross_rows",
			password: []byte{'o', 'p', 'a'},
			limit:    3,
			want:     nil,
		},
		{
			name:     "sequence_in_middle",
			password: []byte{'x', 'q', 'w', 'e', 'x'},
			limit:    3,
			want: []keyboardSequenceViolation{
				{
					offset: 1,
					length: 3,
					layout: "qwerty",
				},
			},
		},
		{
			name:     "direction_change",
			password: []byte{'q', 'w', 'e', 'w', 'q'},
			limit:    3,
			want: []keyboardSequenceViolation{
				{
					offset: 0,
					length: 3,
					layout: "qwerty",
				},
				{
					offset: 2,
					length: 3,
					layout: "qwerty",
				},
			},
		},
		{
			name:     "unknown_character_breaks_sequence",
			password: []byte{'q', 'w', '#', 'e', 'r'},
			limit:    3,
			want:     nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := checkKeyboardSequence(test.password, test.limit, qwertyLayout)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestCheckKeyboardSequenceJCUKEN(t *testing.T) {
	var password []byte

	for _, r := range []rune{'й', 'ц', 'у', 'к'} {
		password = utf8.AppendRune(password, r)
	}

	got := checkKeyboardSequence(password, 3, jcukenLayout)

	assert.Equal(t, []keyboardSequenceViolation{
		{
			offset: 0,
			length: 4,
			layout: "jcuken",
		},
	}, got)
}

func TestCheckKeyboardSequenceJCUKENBackward(t *testing.T) {
	var password []byte

	for _, r := range []rune{'у', 'ц', 'й'} {
		password = utf8.AppendRune(password, r)
	}

	got := checkKeyboardSequence(password, 3, jcukenLayout)

	assert.Equal(t, []keyboardSequenceViolation{
		{
			offset: 0,
			length: 3,
			layout: "jcuken",
		},
	}, got)
}
