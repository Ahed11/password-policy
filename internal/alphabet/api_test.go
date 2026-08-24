package alphabet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuild(t *testing.T) {
	tests := []struct {
		name        string
		definitions []ClassDefinition
		exclude     string
		wantResult  BuildResult
		wantErrors  []string
	}{
		{
			name: "valid_classes",
			definitions: []ClassDefinition{
				{
					Name:     "lower",
					Alphabet: "cba",
				},
				{
					Name:     "digits",
					Alphabet: "210",
				},
			},
			exclude: "",
			wantResult: BuildResult{
				Classes: []Class{
					{
						Name:     "lower",
						Alphabet: []rune{'a', 'b', 'c'},
					},
					{
						Name:     "digits",
						Alphabet: []rune{'0', '1', '2'},
					},
				},
				Union: []rune{'0', '1', '2', 'a', 'b', 'c'},
			},
			wantErrors: []string{},
		},
		{
			name: "exclude_is_applied_before_union",
			definitions: []ClassDefinition{
				{
					Name:     "first",
					Alphabet: "abc",
				},
				{
					Name:     "second",
					Alphabet: "cde",
				},
			},
			exclude: "c",
			wantResult: BuildResult{
				Classes: []Class{
					{
						Name:     "first",
						Alphabet: []rune{'a', 'b'},
					},
					{
						Name:     "second",
						Alphabet: []rune{'d', 'e'},
					},
				},
				Union: []rune{'a', 'b', 'd', 'e'},
			},
			wantErrors: []string{},
		},
		{
			name: "diagnostics_are_returned",
			definitions: []ClassDefinition{
				{
					Name:     "first",
					Alphabet: "aab",
				},
				{
					Name:     "second",
					Alphabet: "bc",
				},
			},
			exclude: "",
			wantResult: BuildResult{
				Classes: []Class{
					{
						Name:     "first",
						Alphabet: []rune{'a', 'b'},
					},
					{
						Name:     "second",
						Alphabet: []rune{'b', 'c'},
					},
				},
				Union: []rune{'a', 'b', 'c'},
			},
			wantErrors: []string{
				`policy.classes["first"].alphabet: duplicate rune 'a'`,
				`classes "first" and "second" share characters: "b"`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotResult, gotErrors := Build(test.definitions, test.exclude)

			gotMessages := []string{}

			for _, err := range gotErrors {
				if err != nil {
					gotMessages = append(gotMessages, err.Error())
				}
			}

			assert.Equal(t, test.wantResult, gotResult)
			assert.Equal(t, test.wantErrors, gotMessages)
		})
	}
}
