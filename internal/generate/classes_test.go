package generate

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPickClassMinimums(t *testing.T) {
	tests := []struct {
		name          string
		classes       []classRequirement
		repeatTotal   bool
		data          []byte
		wantSelected  []rune
		wantUsed      map[rune]struct{}
		wantReadCalls int
	}{
		{
			name: "repeat_total_disabled_allows_duplicates",
			classes: []classRequirement{
				{
					name:     "lower",
					alphabet: []rune{'a', 'b', 'c'},
					min:      2,
				},
			},
			repeatTotal: false,
			data:        []byte{0, 0},
			wantSelected: []rune{
				'a',
				'a',
			},
			wantUsed: map[rune]struct{}{
				'a': {},
			},
			wantReadCalls: 2,
		},
		{
			name: "multiple_classes",
			classes: []classRequirement{
				{
					name:     "lower",
					alphabet: []rune{'a', 'b', 'c'},
					min:      2,
				},
				{
					name:     "digits",
					alphabet: []rune{'0', '1', '2'},
					min:      1,
				},
			},
			repeatTotal: false,
			data: []byte{
				0,
				170,
				85,
			},
			wantSelected: []rune{
				'a',
				'c',
				'1',
			},
			wantUsed: map[rune]struct{}{
				'a': {},
				'c': {},
				'1': {},
			},
			wantReadCalls: 3,
		},
		{
			name: "repeat_total_selects_unique_characters",
			classes: []classRequirement{
				{
					name:     "lower",
					alphabet: []rune{'a', 'b', 'c'},
					min:      3,
				},
			},
			repeatTotal: true,
			data: []byte{
				85,
				128,
			},
			wantSelected: []rune{
				'b',
				'c',
				'a',
			},
			wantUsed: map[rune]struct{}{
				'a': {},
				'b': {},
				'c': {},
			},
			wantReadCalls: 2,
		},
		{
			name: "zero_minimum_is_skipped",
			classes: []classRequirement{
				{
					name:     "optional",
					alphabet: []rune{},
					min:      0,
				},
			},
			repeatTotal:   true,
			data:          []byte{},
			wantSelected:  []rune{},
			wantUsed:      map[rune]struct{}{},
			wantReadCalls: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(test.data)

			gotSelected, gotUsed, err := pickClassMinimums(source, test.classes, test.repeatTotal)

			assert.NoError(t, err)
			assert.Equal(t, test.wantSelected, gotSelected)
			assert.Equal(t, test.wantUsed, gotUsed)
			assert.Equal(t, test.wantReadCalls, source.readCalls)
		})
	}
}

func TestPickClassMinimumsInvalidClass(t *testing.T) {
	tests := []struct {
		name        string
		classes     []classRequirement
		repeatTotal bool
		errContains string
	}{
		{
			name: "empty_alphabet_with_positive_minimum",
			classes: []classRequirement{
				{
					name:     "lower",
					alphabet: []rune{},
					min:      1,
				},
			},
			repeatTotal: false,
			errContains: `class "lower" has an empty alphabet`,
		},
		{
			name: "minimum_exceeds_alphabet_with_repeat_total",
			classes: []classRequirement{
				{
					name:     "digits",
					alphabet: []rune{'0', '1'},
					min:      3,
				},
			},
			repeatTotal: true,
			errContains: `class "digits" requires 3 unique characters, alphabet size is 2`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(nil)

			_, _, err := pickClassMinimums(source, test.classes, test.repeatTotal)

			assert.Error(t, err)
			assert.ErrorContains(t, err, test.errContains)
			assert.Equal(t, 0, source.readCalls)
		})
	}
}

func TestPickClassMinimumsSourceError(t *testing.T) {
	source := newCountingSource(nil)

	_, _, err := pickClassMinimums(
		source,
		[]classRequirement{
			{
				name:     "lower",
				alphabet: []rune{'a', 'b', 'c'},
				min:      1,
			},
		},
		false,
	)

	assert.Error(t, err)
	assert.ErrorContains(t, err, `choose minimum character for class "lower"`)
	assert.ErrorIs(t, err, io.EOF)
}