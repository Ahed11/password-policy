package alphabet

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeClassAlphabet(t *testing.T) {
	tests := []struct {
		name         string
		className    string
		rawAlphabet  string
		exclude      string
		wantRunes    []rune
		wantErrCount int
		wantContains []string
	}{
		{
			name:         "valid_alphabet_is_sorted",
			className:    "lower",
			rawAlphabet:  "cba",
			exclude:      "",
			wantRunes:    []rune{'a', 'b', 'c'},
			wantErrCount: 0,
		},
		{
			name:         "exclude_removes_runes",
			className:    "lower",
			rawAlphabet:  "abcd",
			exclude:      "bd",
			wantRunes:    []rune{'a', 'c'},
			wantErrCount: 0,
		},
		{
			name:         "duplicate_rune",
			className:    "lower",
			rawAlphabet:  "abac",
			exclude:      "",
			wantRunes:    []rune{'a', 'b', 'c'},
			wantErrCount: 1,
			wantContains: []string{
				`policy.classes["lower"].alphabet: duplicate rune 'a'`,
			},
		},
		{
			name:         "duplicate_is_error_even_if_excluded",
			className:    "lower",
			rawAlphabet:  "aabc",
			exclude:      "a",
			wantRunes:    []rune{'b', 'c'},
			wantErrCount: 1,
			wantContains: []string{
				`policy.classes["lower"].alphabet: duplicate rune 'a'`,
			},
		},
		{
			name:         "empty_after_exclude",
			className:    "digits",
			rawAlphabet:  "012",
			exclude:      "012",
			wantRunes:    []rune{},
			wantErrCount: 1,
			wantContains: []string{
				`policy.classes["digits"].alphabet: empty after exclude`,
			},
		},
		{
			name:         "unicode_outside_bmp_is_one_rune",
			className:    "unicode",
			rawAlphabet:  "🌐ba",
			exclude:      "",
			wantRunes:    []rune{'a', 'b', '🌐'},
			wantErrCount: 0,
		},
		{
			name:         "combining_mark_is_rejected",
			className:    "unicode",
			rawAlphabet:  "a\u0301b",
			exclude:      "",
			wantRunes:    []rune{'a', 'b', '\u0301'},
			wantErrCount: 1,
			wantContains: []string{
				`policy.classes["unicode"].alphabet: combining rune`,
			},
		},
		{
			name:         "empty_raw_alphabet",
			className:    "empty",
			rawAlphabet:  "",
			exclude:      "",
			wantRunes:    []rune{},
			wantErrCount: 1,
			wantContains: []string{
				`policy.classes["empty"].alphabet: empty after exclude`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotRunes, gotErrors := normalizeClassAlphabet(test.className, test.rawAlphabet, test.exclude)

			assert.Equal(t, test.wantRunes, gotRunes)
			assert.Len(t, gotErrors, test.wantErrCount)

			for _, expected := range test.wantContains {
				found := false

				for _, err := range gotErrors {
					if err != nil && strings.Contains(err.Error(), expected) {
						found = true
						break
					}
				}

				assert.True(t, found, "expected an error containing %q, got %v", expected, gotErrors)
			}
		})
	}
}

func TestNormalizeClasses(t *testing.T) {
	tests := []struct {
		name        string
		classes     []classDefinition
		exclude     string
		wantClasses []normalizedClass
		wantErrors  []string
	}{
		{
			name:        "no_classes",
			classes:     []classDefinition{},
			exclude:     "",
			wantClasses: []normalizedClass{},
			wantErrors:  []string{},
		},
		{
			name: "multiple_valid_classes",
			classes: []classDefinition{
				{
					name:     "lower",
					alphabet: "cba",
				},
				{
					name:     "digits",
					alphabet: "b21",
				},
			},
			exclude: "b",
			wantClasses: []normalizedClass{
				{
					name:     "lower",
					alphabet: []rune{'a', 'c'},
				},
				{
					name:     "digits",
					alphabet: []rune{'1', '2'},
				},
			},
			wantErrors: []string{},
		},
		{
			name: "collect_errors_from_multiple_classes",
			classes: []classDefinition{
				{
					name:     "first",
					alphabet: "aab",
				},
				{
					name:     "second",
					alphabet: "12",
				},
			},
			exclude: "12",
			wantClasses: []normalizedClass{
				{
					name:     "first",
					alphabet: []rune{'a', 'b'},
				},
				{
					name:     "second",
					alphabet: []rune{},
				},
			},
			wantErrors: []string{
				`policy.classes["first"].alphabet: duplicate rune 'a'`,
				`policy.classes["second"].alphabet: empty after exclude`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotClasses, gotErrors := normalizeClasses(test.classes, test.exclude)

			gotMessages := []string{}

			for _, err := range gotErrors {
				if err != nil {
					gotMessages = append(gotMessages, err.Error())
				}
			}

			assert.Equal(t, test.wantClasses, gotClasses)
			assert.Equal(t, test.wantErrors, gotMessages)
		})
	}
}

func TestBuildClasses(t *testing.T) {
	tests := []struct {
		name        string
		classes     []classDefinition
		exclude     string
		wantClasses []normalizedClass
		wantErrors  []string
	}{
		{
			name: "valid_classes",
			classes: []classDefinition{
				{
					name:     "lower",
					alphabet: "cba",
				},
				{
					name:     "digits",
					alphabet: "210",
				},
			},
			exclude: "",
			wantClasses: []normalizedClass{
				{
					name:     "lower",
					alphabet: []rune{'a', 'b', 'c'},
				},
				{
					name:     "digits",
					alphabet: []rune{'0', '1', '2'},
				},
			},
			wantErrors: []string{},
		},
		{
			name: "exclude_removes_intersection",
			classes: []classDefinition{
				{
					name:     "first",
					alphabet: "abc",
				},
				{
					name:     "second",
					alphabet: "cde",
				},
			},
			exclude: "c",
			wantClasses: []normalizedClass{
				{
					name:     "first",
					alphabet: []rune{'a', 'b'},
				},
				{
					name:     "second",
					alphabet: []rune{'d', 'e'},
				},
			},
			wantErrors: []string{},
		},
		{
			name: "normalization_and_intersection_errors",
			classes: []classDefinition{
				{
					name:     "first",
					alphabet: "aab",
				},
				{
					name:     "second",
					alphabet: "bc",
				},
			},
			exclude: "",
			wantClasses: []normalizedClass{
				{
					name:     "first",
					alphabet: []rune{'a', 'b'},
				},
				{
					name:     "second",
					alphabet: []rune{'b', 'c'},
				},
			},
			wantErrors: []string{
				`policy.classes["first"].alphabet: duplicate rune 'a'`,
				`classes "first" and "second" share characters: "b"`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotClasses, gotErrors := buildClasses(test.classes, test.exclude)

			gotMessages := []string{}

			for _, err := range gotErrors {
				if err != nil {
					gotMessages = append(gotMessages, err.Error())
				}
			}

			assert.Equal(t, test.wantClasses, gotClasses)
			assert.Equal(t, test.wantErrors, gotMessages)
		})
	}
}