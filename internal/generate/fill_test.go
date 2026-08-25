package generate

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFillToLength(t *testing.T) {
	tests := []struct {
		name          string
		selected      []rune
		used          map[rune]struct{}
		unionAlphabet []rune
		targetLength  int
		repeatTotal   bool
		data          []byte
		want          []rune
		wantReadCalls int
	}{
		{
			name:          "already_at_target_length",
			selected:      []rune{'a', '1'},
			used:          map[rune]struct{}{'a': {}, '1': {}},
			unionAlphabet: []rune{'a', 'b', '0', '1'},
			targetLength:  2,
			repeatTotal:   false,
			data:          []byte{},
			want:          []rune{'a', '1'},
			wantReadCalls: 0,
		},
		{
			name:          "repeat_total_disabled_allows_duplicates",
			selected:      []rune{'a'},
			used:          map[rune]struct{}{'a': {}},
			unionAlphabet: []rune{'a', 'b', 'c'},
			targetLength:  3,
			repeatTotal:   false,
			data:          []byte{0, 0},
			want:          []rune{'a', 'a', 'a'},
			wantReadCalls: 2,
		},
		{
			name:     "repeat_total_excludes_used_characters",
			selected: []rune{'a', '1'},
			used: map[rune]struct{}{
				'a': {},
				'1': {},
			},
			unionAlphabet: []rune{'a', 'b', 'c', '0', '1', '2'},
			targetLength:  5,
			repeatTotal:   true,
			data:          []byte{0, 0, 0},
			want:          []rune{'a', '1', 'b', '2', '0'},
			wantReadCalls: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(test.data)

			got, err := fillToLength(
				source,
				test.selected,
				test.used,
				test.unionAlphabet,
				test.targetLength,
				test.repeatTotal,
			)

			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.wantReadCalls, source.readCalls)
		})
	}
}

func TestFillToLengthInvalidInput(t *testing.T) {
	tests := []struct {
		name          string
		selected      []rune
		used          map[rune]struct{}
		unionAlphabet []rune
		targetLength  int
		repeatTotal   bool
		errContains   string
	}{
		{
			name:          "selected_exceeds_target_length",
			selected:      []rune{'a', 'b', 'c'},
			used:          map[rune]struct{}{},
			unionAlphabet: []rune{'a', 'b', 'c'},
			targetLength:  2,
			repeatTotal:   false,
			errContains:   "selected character count 3 exceeds target length 2",
		},
		{
			name:          "empty_union_alphabet",
			selected:      []rune{'a'},
			used:          map[rune]struct{}{'a': {}},
			unionAlphabet: []rune{},
			targetLength:  2,
			repeatTotal:   false,
			errContains:   "cannot fill password to length 2: union alphabet is empty",
		},
		{
			name:     "not_enough_unused_characters",
			selected: []rune{'a'},
			used: map[rune]struct{}{
				'a': {},
			},
			unionAlphabet: []rune{'a', 'b'},
			targetLength:  3,
			repeatTotal:   true,
			errContains:   "not enough unused characters to fill password: need 2, available 1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := newCountingSource(nil)

			_, err := fillToLength(source, test.selected, test.used, test.unionAlphabet, test.targetLength, test.repeatTotal)

			assert.Error(t, err)
			assert.ErrorContains(t, err, test.errContains)
			assert.Equal(t, 0, source.readCalls)
		})
	}
}

func TestFillToLengthSourceError(t *testing.T) {
	source := newCountingSource(nil)

	_, err := fillToLength(source, []rune{'a'}, map[rune]struct{}{'a': {}}, []rune{'a', 'b', 'c'}, 2, false)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "choose fill character 1 of 1")
	assert.ErrorIs(t, err, io.EOF)
}

func TestFillToLengthUpdatesUsed(t *testing.T) {
	used := map[rune]struct{}{
		'a': {},
		'1': {},
	}

	source := newCountingSource([]byte{0, 0, 0})

	got, err := fillToLength(source, []rune{'a', '1'}, used, []rune{'a', 'b', 'c', '0', '1', '2'}, 5, true)

	assert.NoError(t, err)
	assert.Equal(t, []rune{'a', '1', 'b', '2', '0'}, got)

	assert.Contains(t, used, 'a')
	assert.Contains(t, used, '1')
	assert.Contains(t, used, 'b')
	assert.Contains(t, used, '2')
	assert.Contains(t, used, '0')
}
