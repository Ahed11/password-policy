package rules

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestCheckContext(t *testing.T) {
	tests := []struct {
		name            string
		password        []byte
		values          []string
		minLength       int
		caseInsensitive bool
		leet            bool
		want            []contextViolation
	}{
		{
			name:            "empty_context",
			password:        []byte{'a', 'b', 'c'},
			values:          nil,
			minLength:       3,
			caseInsensitive: false,
			leet:            false,
			want:            nil,
		},
		{
			name:            "context_value_shorter_than_min_length",
			password:        []byte{'a', 'b'},
			values:          []string{"ab"},
			minLength:       3,
			caseInsensitive: false,
			leet:            false,
			want:            nil,
		},
		{
			name:            "no_match",
			password:        []byte{'x', 'y', 'z'},
			values:          []string{"admin"},
			minLength:       3,
			caseInsensitive: false,
			leet:            false,
			want:            nil,
		},
		{
			name:            "direct_match",
			password:        []byte{'X', 'a', 'd', 'm', 'i', 'n', '!'},
			values:          []string{"admin"},
			minLength:       5,
			caseInsensitive: false,
			leet:            false,
			want: []contextViolation{
				{
					offset: 1,
					length: 5,
				},
			},
		},
		{
			name:            "substring_inside_context_value",
			password:        []byte{'X', 'r', 'v', 'i', '!'},
			values:          []string{"service"},
			minLength:       3,
			caseInsensitive: false,
			leet:            false,
			want: []contextViolation{
				{
					offset: 1,
					length: 3,
				},
			},
		},
		{
			name:            "reversed_match",
			password:        []byte{'X', 'r', 'e', 's', '!'},
			values:          []string{"service"},
			minLength:       3,
			caseInsensitive: false,
			leet:            false,
			want: []contextViolation{
				{
					offset: 1,
					length: 3,
				},
			},
		},
		{
			name:            "case_insensitive",
			password:        []byte{'X', 'A', 'D', 'M', 'I', 'N', '!'},
			values:          []string{"Admin"},
			minLength:       5,
			caseInsensitive: true,
			leet:            false,
			want: []contextViolation{
				{
					offset: 1,
					length: 5,
				},
			},
		},
		{
			name:            "case_sensitive_different_case",
			password:        []byte{'A', 'D', 'M', 'I', 'N'},
			values:          []string{"admin"},
			minLength:       5,
			caseInsensitive: false,
			leet:            false,
			want:            nil,
		},
		{
			name:            "leet",
			password:        []byte{'4', 'd', 'm', 'i', 'n'},
			values:          []string{"admin"},
			minLength:       5,
			caseInsensitive: false,
			leet:            true,
			want: []contextViolation{
				{
					offset: 0,
					length: 5,
				},
			},
		},
		{
			name:            "multiple_leet_substitutions",
			password:        []byte{'p', '4', '$', '$', 'w', '0', 'r', 'd'},
			values:          []string{"password"},
			minLength:       8,
			caseInsensitive: false,
			leet:            true,
			want: []contextViolation{
				{
					offset: 0,
					length: 8,
				},
			},
		},
		{
			name:            "leet_disabled",
			password:        []byte{'4', 'd', 'm', 'i', 'n'},
			values:          []string{"admin"},
			minLength:       5,
			caseInsensitive: false,
			leet:            false,
			want:            nil,
		},
		{
			name:            "case_insensitive_and_leet",
			password:        []byte{'P', '4', '$', '$', 'W', '0', 'R', 'D'},
			values:          []string{"Password"},
			minLength:       8,
			caseInsensitive: true,
			leet:            true,
			want: []contextViolation{
				{
					offset: 0,
					length: 8,
				},
			},
		},
		{
			name:            "multiple_context_values",
			password:        []byte{'c', 'a', 't', 'X', 'd', 'o', 'g'},
			values:          []string{"cat", "dog"},
			minLength:       3,
			caseInsensitive: false,
			leet:            false,
			want: []contextViolation{
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
			name:            "palindrome_is_not_reported_twice",
			password:        []byte{'a', 'b', 'a'},
			values:          []string{"aba"},
			minLength:       3,
			caseInsensitive: false,
			leet:            false,
			want: []contextViolation{
				{
					offset: 0,
					length: 3,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := checkContext(
				test.password,
				test.values,
				test.minLength,
				test.caseInsensitive,
				test.leet,
			)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestCheckContextUnicode(t *testing.T) {
	var password []byte

	for _, r := range []rune{'x', 'к', 'о', 'т', 'y'} {
		password = utf8.AppendRune(password, r)
	}

	got := checkContext(password, []string{"котик"}, 3, false, false)

	assert.Equal(t, []contextViolation{
		{
			offset: 1,
			length: 3,
		},
	}, got)
}
