package dictionary

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestSearchTrie(t *testing.T) {
	tests := []struct {
		name            string
		password        []byte
		words           []string
		caseInsensitive bool
		want            []dictionaryMatch
	}{
		{
			name:            "no_match",
			password:        []byte{'x', 'y', 'z'},
			words:           []string{"admin", "root"},
			caseInsensitive: false,
			want:            nil,
		},
		{
			name:            "whole_password_matches",
			password:        []byte{'a', 'd', 'm', 'i', 'n'},
			words:           []string{"admin"},
			caseInsensitive: false,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 5,
				},
			},
		},
		{
			name:            "match_in_middle",
			password:        []byte{'X', '7', 'a', 'd', 'm', 'i', 'n', '!'},
			words:           []string{"admin"},
			caseInsensitive: false,
			want: []dictionaryMatch{
				{
					offset: 2,
					length: 5,
				},
			},
		},
		{
			name:            "match_at_end",
			password:        []byte{'X', '7', 'r', 'o', 'o', 't'},
			words:           []string{"root"},
			caseInsensitive: false,
			want: []dictionaryMatch{
				{
					offset: 2,
					length: 4,
				},
			},
		},
		{
			name:            "multiple_matches",
			password:        []byte{'c', 'a', 't', 'X', 'd', 'o', 'g'},
			words:           []string{"cat", "dog"},
			caseInsensitive: false,
			want: []dictionaryMatch{
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
			name:            "word_is_prefix_of_another_word",
			password:        []byte{'c', 'a', 'r', 't'},
			words:           []string{"car", "cart"},
			caseInsensitive: false,
			want: []dictionaryMatch{
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
		{
			name:            "case_insensitive",
			password:        []byte{'X', 'A', 'd', 'M', 'i', 'N', '7'},
			words:           []string{"admin"},
			caseInsensitive: true,
			want: []dictionaryMatch{
				{
					offset: 1,
					length: 5,
				},
			},
		},
		{
			name:            "case_sensitive_does_not_match_different_case",
			password:        []byte{'A', 'D', 'M', 'I', 'N'},
			words:           []string{"admin"},
			caseInsensitive: false,
			want:            nil,
		},
		{
			name:            "empty_password",
			password:        nil,
			words:           []string{"admin"},
			caseInsensitive: false,
			want:            nil,
		},
		{
			name:            "empty_trie",
			password:        []byte{'a', 'd', 'm', 'i', 'n'},
			words:           nil,
			caseInsensitive: false,
			want:            nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := buildTrie(test.words)

			got := searchTrie(test.password, tree, test.caseInsensitive, false)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestSearchTrieUnicode(t *testing.T) {
	var password []byte

	for _, r := range []rune{'x', 'к', 'о', 'т', 'y'} {
		password = utf8.AppendRune(password, r)
	}

	tree := buildTrie([]string{"кот"})

	got := searchTrie(password, tree, false, false)

	assert.Equal(t, []dictionaryMatch{
		{
			offset: 1,
			length: 3,
		},
	}, got)
}

func TestSearchTrieNilTrie(t *testing.T) {
	got := searchTrie([]byte{'a', 'd', 'm', 'i', 'n'}, nil, false, false)

	assert.Nil(t, got)
}

func TestSearchTrieLeet(t *testing.T) {
	tests := []struct {
		name            string
		password        []byte
		words           []string
		caseInsensitive bool
		leet            bool
		want            []dictionaryMatch
	}{
		{
			name:            "leet_disabled",
			password:        []byte{'4', 'd', 'm', 'i', 'n'},
			words:           []string{"admin"},
			caseInsensitive: false,
			leet:            false,
			want:            nil,
		},
		{
			name:            "four_to_a",
			password:        []byte{'4', 'd', 'm', 'i', 'n'},
			words:           []string{"admin"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 5,
				},
			},
		},
		{
			name:            "at_to_a",
			password:        []byte{'@', 'd', 'm', 'i', 'n'},
			words:           []string{"admin"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 5,
				},
			},
		},
		{
			name:            "three_to_e",
			password:        []byte{'t', '3', 's', 't'},
			words:           []string{"test"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:            "one_to_l",
			password:        []byte{'1', 'o', 'g', 'i', 'n'},
			words:           []string{"login"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 5,
				},
			},
		},
		{
			name:            "zero_to_o",
			password:        []byte{'r', '0', '0', 't'},
			words:           []string{"root"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:            "five_to_s",
			password:        []byte{'p', 'a', '5', '5'},
			words:           []string{"pass"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:            "dollar_to_s",
			password:        []byte{'p', 'a', '$', '$'},
			words:           []string{"pass"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:            "seven_to_t",
			password:        []byte{'t', 'e', 's', '7'},
			words:           []string{"test"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 4,
				},
			},
		},
		{
			name:            "multiple_leet_substitutions",
			password:        []byte{'p', '4', '$', '$', 'w', '0', 'r', 'd'},
			words:           []string{"password"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 8,
				},
			},
		},
		{
			name:            "leet_and_case_insensitive",
			password:        []byte{'P', '4', '$', '$', 'W', '0', 'R', 'D'},
			words:           []string{"password"},
			caseInsensitive: true,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 0,
					length: 8,
				},
			},
		},
		{
			name:            "leet_match_in_middle",
			password:        []byte{'X', '7', 'p', '4', '$', '$', 'w', '0', 'r', 'd', '!'},
			words:           []string{"password"},
			caseInsensitive: false,
			leet:            true,
			want: []dictionaryMatch{
				{
					offset: 2,
					length: 8,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := buildTrie(test.words)

			got := searchTrie(test.password, tree, test.caseInsensitive, test.leet)

			assert.Equal(t, test.want, got)
		})
	}
}
