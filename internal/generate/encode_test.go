package generate

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestEncodeRunes(t *testing.T) {
	tests := []struct {
		name   string
		values []rune
		want   []byte
	}{
		{
			name:   "ascii",
			values: []rune{'a', 'B', '7'},
			want:   []byte{0x61, 0x42, 0x37},
		},
		{
			name:   "multi_byte_unicode",
			values: []rune{'Ж'},
			want:   []byte{0xD0, 0x96},
		},
		{
			name:   "rune_outside_bmp",
			values: []rune{'😀'},
			want:   []byte{0xF0, 0x9F, 0x98, 0x80},
		},
		{
			name:   "mixed",
			values: []rune{'a', 'Ж', '😀', '7'},
			want: []byte{
				0x61,
				0xD0, 0x96,
				0xF0, 0x9F, 0x98, 0x80,
				0x37,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := encodeRunes(test.values)

			assert.Equal(t, test.want, got)
			assert.True(t, utf8.Valid(got))
		})
	}
}

func TestEncodeRunesEmpty(t *testing.T) {
	got := encodeRunes(nil)

	assert.Empty(t, got)
	assert.True(t, utf8.Valid(got))
}
