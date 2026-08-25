package generate

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShuffleRunes(t *testing.T) {
	tests := []struct {
		name          string
		values        []rune
		data          []byte
		want          []rune
		wantReadCalls int
	}{
		{
			name:          "shuffle_multiple_runes",
			values:        []rune{'a', 'b', 'c', 'd'},
			data:          []byte{0, 0, 0},
			want:          []rune{'b', 'c', 'd', 'a'},
			wantReadCalls: 3,
		},
		{
			name:          "empty_slice",
			values:        []rune{},
			data:          nil,
			want:          []rune{},
			wantReadCalls: 0,
		},
		{
			name:          "single_rune",
			values:        []rune{'a'},
			data:          nil,
			want:          []rune{'a'},
			wantReadCalls: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(test.data)

			values := append([]rune{}, test.values...)

			err := shuffleRunes(source, values)

			assert.NoError(t, err)
			assert.Equal(t, test.want, values)
			assert.Equal(t, test.wantReadCalls, source.readCalls)
		})
	}
}

func TestShuffleRunesSourceError(t *testing.T) {
	source := newCountingSource(nil)
	values := []rune{'a', 'b'}

	err := shuffleRunes(source, values)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "shuffle password characters")
	assert.ErrorIs(t, err, io.EOF)
}
