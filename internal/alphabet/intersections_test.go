package alphabet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntersectSortedRunes(t *testing.T) {
	tests := []struct {
		name  string
		left  []rune
		right []rune
		want  []rune
	}{
		{
			name:  "no_intersection",
			left:  []rune{'a', 'b'},
			right: []rune{'c', 'd'},
			want:  []rune{},
		},
		{
			name:  "one_common_rune",
			left:  []rune{'a', 'b', 'c'},
			right: []rune{'b'},
			want:  []rune{'b'},
		},
		{
			name:  "multiple_common_runes",
			left:  []rune{'a', 'b', 'c', 'd'},
			right: []rune{'b', 'd', 'x'},
			want:  []rune{'b', 'd'},
		},
		{
			name:  "left_is_empty",
			left:  []rune{},
			right: []rune{'a', 'b'},
			want:  []rune{},
		},
		{
			name:  "right_is_empty",
			left:  []rune{'a', 'b'},
			right: []rune{},
			want:  []rune{},
		},
		{
			name:  "same_alphabets",
			left:  []rune{'a', 'b', 'c'},
			right: []rune{'a', 'b', 'c'},
			want:  []rune{'a', 'b', 'c'},
		},
		{
			name:  "non_bmp_rune",
			left:  []rune{'a', '🌐'},
			right: []rune{'b', '🌐'},
			want:  []rune{'🌐'},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := intersectSortedRunes(test.left, test.right)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestValidateClassIntersections(t *testing.T) {
	tests := []struct {
		name    string
		classes []normalizedClass
		want    []string
	}{
		{
			name:    "no_classes",
			classes: []normalizedClass{},
			want:    []string{},
		},
		{
			name: "one_class",
			classes: []normalizedClass{
				{
					name:     "lower",
					alphabet: []rune{'a', 'b', 'c'},
				},
			},
			want: []string{},
		},
		{
			name: "no_intersections",
			classes: []normalizedClass{
				{
					name:     "lower",
					alphabet: []rune{'a', 'b', 'c'},
				},
				{
					name:     "digits",
					alphabet: []rune{'0', '1', '2'},
				},
				{
					name:     "upper",
					alphabet: []rune{'A', 'B', 'C'},
				},
			},
			want: []string{},
		},
		{
			name: "one_shared_rune",
			classes: []normalizedClass{
				{
					name:     "first",
					alphabet: []rune{'a', 'b', 'c'},
				},
				{
					name:     "second",
					alphabet: []rune{'b', 'd', 'e'},
				},
			},
			want: []string{
				`classes "first" and "second" share characters: "b"`,
			},
		},
		{
			name: "multiple_shared_runes",
			classes: []normalizedClass{
				{
					name:     "lower",
					alphabet: []rune{'a', 'x', 'y'},
				},
				{
					name:     "extra",
					alphabet: []rune{'x', 'y', 'z'},
				},
			},
			want: []string{
				`classes "lower" and "extra" share characters: "x", "y"`,
			},
		},
		{
			name: "multiple_intersecting_pairs",
			classes: []normalizedClass{
				{
					name:     "first",
					alphabet: []rune{'a', 'b', 'c'},
				},
				{
					name:     "second",
					alphabet: []rune{'b', 'c', 'd'},
				},
				{
					name:     "third",
					alphabet: []rune{'c', 'x'},
				},
			},
			want: []string{
				`classes "first" and "second" share characters: "b", "c"`,
				`classes "first" and "third" share characters: "c"`,
				`classes "second" and "third" share characters: "c"`,
			},
		},
		{
			name: "non_bmp_intersection",
			classes: []normalizedClass{
				{
					name:     "first",
					alphabet: []rune{'a', '🌐'},
				},
				{
					name:     "second",
					alphabet: []rune{'b', '🌐'},
				},
			},
			want: []string{
				`classes "first" and "second" share characters: "🌐"`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErrors := validateClassIntersections(test.classes)

			gotMessages := []string{}

			for _, err := range gotErrors {
				if err != nil {
					gotMessages = append(gotMessages, err.Error())
				}
			}

			assert.Equal(t, test.want, gotMessages)
		})
	}
}
