package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ahed11/password-policy/internal/dictionary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDictionary(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		password []byte
		want     []dictionaryViolation
	}{
		{
			name:     "no_match",
			content:  "admin\nroot\n",
			password: []byte{'x', 'y', 'z'},
			want:     nil,
		},
		{
			name:     "single_match",
			content:  "admin\nroot\n",
			password: []byte{'X', '7', 'a', 'd', 'm', 'i', 'n', '!'},
			want: []dictionaryViolation{
				{
					offset: 2,
					length: 5,
				},
			},
		},
		{
			name:     "multiple_matches",
			content:  "cat\ndog\n",
			password: []byte{'c', 'a', 't', 'X', 'd', 'o', 'g'},
			want: []dictionaryViolation{
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
			name:     "prefix_matches",
			content:  "car\ncart\n",
			password: []byte{'c', 'a', 'r', 't'},
			want: []dictionaryViolation{
				{
					offset: 0,
					length: 3,
				},
				{
					offset: 0,
					length: 4,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "dictionary.txt")

			err := os.WriteFile(path, []byte(test.content), 0600)
			require.NoError(t, err)

			matcher, err := dictionary.Load(path, 1, false, false)
			require.NoError(t, err)

			got := checkDictionary(test.password, matcher)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestCheckDictionaryNilMatcher(t *testing.T) {
	got := checkDictionary([]byte{'a', 'd', 'm', 'i', 'n'}, nil)

	assert.Nil(t, got)
}

func TestCheckDictionaryEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary.txt")

	err := os.WriteFile(path, []byte("admin\n"), 0600)
	require.NoError(t, err)

	matcher, err := dictionary.Load(path, 1, false, false)
	require.NoError(t, err)

	got := checkDictionary(nil, matcher)

	assert.Nil(t, got)
}