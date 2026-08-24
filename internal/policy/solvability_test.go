package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateClassMinimumSum(t *testing.T) {
	tests := []struct {
		name       string
		classes    []Class
		lengthMax  int
		wantErrors []string
	}{
		{
			name: "sum_less_than_length_max",
			classes: []Class{
				{
					Name: "digits",
					Min:  2,
				},
				{
					Name: "lower",
					Min:  2,
				},
				{
					Name: "special",
					Min:  1,
				},
			},
			lengthMax:  12,
			wantErrors: []string{},
		},
		{
			name: "sum_equals_length_max",
			classes: []Class{
				{
					Name: "digits",
					Min:  2,
				},
				{
					Name: "lower",
					Min:  2,
				},
				{
					Name: "special",
					Min:  1,
				},
			},
			lengthMax:  5,
			wantErrors: []string{},
		},
		{
			name: "sum_greater_than_length_max",
			classes: []Class{
				{
					Name: "digits",
					Min:  2,
				},
				{
					Name: "lower",
					Min:  2,
				},
				{
					Name: "upper",
					Min:  2,
				},
			},
			lengthMax: 5,
			wantErrors: []string{
				"sum of class minimums is 6, length.max is 5",
			},
		},
		{
			name: "zero_class_minimums_are_allowed",
			classes: []Class{
				{
					Name: "digits",
					Min:  0,
				},
				{
					Name: "lower",
					Min:  0,
				},
				{
					Name: "special",
					Min:  1,
				},
			},
			lengthMax:  1,
			wantErrors: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErrors := validateClassMinimumSum(test.classes, test.lengthMax)

			gotMessages := []string{}

			for _, err := range gotErrors {
				if err != nil {
					gotMessages = append(gotMessages, err.Error())
				}
			}

			assert.Equal(t, test.wantErrors, gotMessages)
		})
	}
}

func TestValidateRepeatTotalCapacity(t *testing.T) {
	tests := []struct {
		name              string
		repeatTotal       bool
		lengthMax         int
		unionAlphabetSize int
		classes           []classCapacity
		wantErrors        []string
	}{
		{
			name:              "repeat_total_disabled",
			repeatTotal:       false,
			lengthMax:         20,
			unionAlphabetSize: 5,
			classes: []classCapacity{
				{
					name:         "digits",
					min:          10,
					alphabetSize: 3,
				},
			},
			wantErrors: []string{},
		},
		{
			name:              "valid_capacity",
			repeatTotal:       true,
			lengthMax:         8,
			unionAlphabetSize: 10,
			classes: []classCapacity{
				{
					name:         "digits",
					min:          2,
					alphabetSize: 10,
				},
				{
					name:         "lower",
					min:          3,
					alphabetSize: 26,
				},
			},
			wantErrors: []string{},
		},
		{
			name:              "capacity_on_boundary",
			repeatTotal:       true,
			lengthMax:         10,
			unionAlphabetSize: 10,
			classes: []classCapacity{
				{
					name:         "digits",
					min:          10,
					alphabetSize: 10,
				},
			},
			wantErrors: []string{},
		},
		{
			name:              "union_alphabet_too_small",
			repeatTotal:       true,
			lengthMax:         11,
			unionAlphabetSize: 10,
			classes: []classCapacity{
				{
					name:         "digits",
					min:          2,
					alphabetSize: 10,
				},
			},
			wantErrors: []string{
				"policy.length.max: value 11 exceeds union alphabet size 10",
			},
		},
		{
			name:              "class_alphabet_too_small",
			repeatTotal:       true,
			lengthMax:         10,
			unionAlphabetSize: 20,
			classes: []classCapacity{
				{
					name:         "digits",
					min:          6,
					alphabetSize: 5,
				},
			},
			wantErrors: []string{
				`policy.classes["digits"].min: value 6 exceeds alphabet size 5`,
			},
		},
		{
			name:              "union_and_class_capacity_errors",
			repeatTotal:       true,
			lengthMax:         12,
			unionAlphabetSize: 10,
			classes: []classCapacity{
				{
					name:         "digits",
					min:          6,
					alphabetSize: 5,
				},
			},
			wantErrors: []string{
				"policy.length.max: value 12 exceeds union alphabet size 10",
				`policy.classes["digits"].min: value 6 exceeds alphabet size 5`,
			},
		},
		{
			name:              "multiple_class_capacity_errors",
			repeatTotal:       true,
			lengthMax:         8,
			unionAlphabetSize: 20,
			classes: []classCapacity{
				{
					name:         "digits",
					min:          6,
					alphabetSize: 5,
				},
				{
					name:         "lower",
					min:          4,
					alphabetSize: 3,
				},
			},
			wantErrors: []string{
				`policy.classes["digits"].min: value 6 exceeds alphabet size 5`,
				`policy.classes["lower"].min: value 4 exceeds alphabet size 3`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErrors := validateRepeatTotalCapacity(test.repeatTotal, test.lengthMax, test.unionAlphabetSize, test.classes)

			gotMessages := []string{}

			for _, err := range gotErrors {
				if err != nil {
					gotMessages = append(gotMessages, err.Error())
				}
			}

			assert.Equal(t, test.wantErrors, gotMessages)
		})
	}
}
