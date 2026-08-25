package generate

import (
	"io"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestBuildCandidate(t *testing.T) {
	classes := []classRequirement{
		{
			name:     "digits",
			alphabet: []rune{'0', '1'},
			min:      1,
		},
		{
			name:     "lower",
			alphabet: []rune{'a', 'b'},
			min:      1,
		},
	}

	unionAlphabet := []rune{'0', '1', 'a', 'b'}

	source := newCountingSource([]byte{
		0, 0,
		0, 0,
		0, 0, 0,
	})

	got, err := buildCandidate(source, 4, 4, classes, unionAlphabet, false)

	assert.NoError(t, err)
	assert.Equal(t, []byte{'a', '0', '0', '0'}, got)
	assert.Equal(t, 4, utf8.RuneCount(got))
	assert.Equal(t, 7, source.readCalls)
}

func TestBuildCandidateRepeatTotal(t *testing.T) {
	classes := []classRequirement{
		{
			name:     "digits",
			alphabet: []rune{'0', '1'},
			min:      1,
		},
		{
			name:     "lower",
			alphabet: []rune{'a', 'b'},
			min:      1,
		},
	}

	unionAlphabet := []rune{'0', '1', 'a', 'b'}

	source := newCountingSource([]byte{
		0, 0,
		0,
		0, 0, 0,
	})

	got, err := buildCandidate(source, 4, 4, classes, unionAlphabet, true)

	assert.NoError(t, err)
	assert.Equal(t, []byte{'a', '1', 'b', '0'}, got)
	assert.Equal(t, 4, utf8.RuneCount(got))
	assert.Equal(t, 6, source.readCalls)
}

func TestBuildCandidateSourceError(t *testing.T) {
	source := newCountingSource(nil)

	_, err := buildCandidate(source, 3, 4, nil, []rune{'a', 'b'}, false)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "build candidate")
	assert.ErrorContains(t, err, "choose password length")
	assert.ErrorIs(t, err, io.EOF)
}

func TestBuildCandidateLengthTooShortForClassMinimums(t *testing.T) {
	classes := []classRequirement{
		{
			name:     "digits",
			alphabet: []rune{'0', '1'},
			min:      2,
		},
		{
			name:     "lower",
			alphabet: []rune{'a', 'b'},
			min:      1,
		},
	}

	source := newCountingSource([]byte{0})

	_, err := buildCandidate(source, 2, 3, classes, []rune{'0', '1', 'a', 'b'}, false)

	assert.Error(t, err)
	assert.ErrorIs(t, err, errCandidateLengthTooShort)
	assert.ErrorContains(t, err, "target length 2")
	assert.ErrorContains(t, err, "class minimum total 3")
	assert.Equal(t, 1, source.readCalls)
}
