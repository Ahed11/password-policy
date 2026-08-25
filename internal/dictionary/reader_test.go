package dictionary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadWords(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		minLength       int
		caseInsensitive bool
		want            []string
	}{
		{
			name: "reads_words",
			content: "alpha\n" +
				"beta\n" +
				"gamma\n",
			minLength:       1,
			caseInsensitive: false,
			want:            []string{"alpha", "beta", "gamma"},
		},
		{
			name: "skips_empty_lines",
			content: "alpha\n" +
				"\n" +
				"beta\n" +
				"\n",
			minLength:       1,
			caseInsensitive: false,
			want:            []string{"alpha", "beta"},
		},
		{
			name: "skips_words_shorter_than_min_length",
			content: "cat\n" +
				"door\n" +
				"password\n",
			minLength:       4,
			caseInsensitive: false,
			want:            []string{"door", "password"},
		},
		{
			name: "keeps_word_exactly_at_min_length",
			content: "cat\n" +
				"door\n",
			minLength:       4,
			caseInsensitive: false,
			want:            []string{"door"},
		},
		{
			name: "case_insensitive",
			content: "Password\n" +
				"ADMIN\n" +
				"Service\n",
			minLength:       1,
			caseInsensitive: true,
			want:            []string{"password", "admin", "service"},
		},
		{
			name: "case_sensitive_preserves_case",
			content: "Password\n" +
				"ADMIN\n",
			minLength:       1,
			caseInsensitive: false,
			want:            []string{"Password", "ADMIN"},
		},
		{
			name: "unicode_length_is_counted_in_runes",
			content: "кот\n" +
				"слон\n" +
				"😀😀😀😀\n",
			minLength:       4,
			caseInsensitive: false,
			want:            []string{"слон", "😀😀😀😀"},
		},
		{
			name: "unicode_case_insensitive",
			content: "ПАРОЛЬ\n" +
				"Сервис\n",
			minLength:       1,
			caseInsensitive: true,
			want:            []string{"пароль", "сервис"},
		},
		{
			name: "handles_crlf",
			content: "alpha\r\n" +
				"beta\r\n",
			minLength:       1,
			caseInsensitive: false,
			want:            []string{"alpha", "beta"},
		},
		{
			name:            "reads_last_line_without_newline",
			content:         "alpha\nbeta",
			minLength:       1,
			caseInsensitive: false,
			want:            []string{"alpha", "beta"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "dictionary.txt")

			err := os.WriteFile(path, []byte(test.content), 0600)
			require.NoError(t, err)

			got, err := readWords(path, test.minLength, test.caseInsensitive)

			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestReadWordsEmptyPath(t *testing.T) {
	got, err := readWords("", 4, true)

	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestReadWordsUnavailableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")

	_, err := readWords(path, 4, true)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "check dictionary availability")
}
