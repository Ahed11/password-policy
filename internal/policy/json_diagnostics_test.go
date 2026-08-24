package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateJSONFields(t *testing.T) {
	tests := []struct {
		name       string
		jsonDoc    []byte
		wantErrors []string
	}{
		{
			name: "valid_json",
			jsonDoc: []byte(`{
				"version": 1,
				"policy": {
					"name": "test",
					"length": {
						"min": 12,
						"max": 20
					},
					"classes": [
						{
							"name": "digits",
							"alphabet": "0123456789",
							"min": 2
						}
					]
				}
			}`),
			wantErrors: []string{},
		},
		{
			name: "one_unknown_field",
			jsonDoc: []byte(`{
				"version": 1,
				"policy": {
					"length": {
						"min": 12,
						"max": 20,
						"foo": 100
					}
				}
			}`),
			wantErrors: []string{
				"policy.length.foo: unknown field",
			},
		},
		{
			name: "multiple_unknown_fields",
			jsonDoc: []byte(`{
				"version": 1,
				"policy": {
					"length": {
						"foo": 100,
						"bar": 20
					}
				}
			}`),
			wantErrors: []string{
				"policy.length.foo: unknown field",
				"policy.length.bar: unknown field",
			},
		},
		{
			name: "unknown_field_inside_classes",
			jsonDoc: []byte(`{
				"version": 1,
				"policy": {
					"classes": [
						{
							"name": "digits",
							"alphabet": "0123456789",
							"foo": 100
						}
					]
				}
			}`),
			wantErrors: []string{
				"policy.classes[0].foo: unknown field",
			},
		},
		{
			name: "unknown_complex_value_does_not_stop_walker",
			jsonDoc: []byte(`{
				"version": 1,
				"policy": {
					"length": {
						"foo": {
							"nested": [
								1,
								2,
								{
									"value": 3
								}
							]
						},
						"bar": 20
					}
				}
			}`),
			wantErrors: []string{
				"policy.length.foo: unknown field",
				"policy.length.bar: unknown field",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostics, err := validateJSONFields(test.jsonDoc)

			if err != nil {
				t.Fatalf("unexpected JSON validation error: %v", err)
			}

			messages := []string{}

			for _, diagnosticErr := range diagnostics {
				if diagnosticErr != nil {
					messages = append(messages, diagnosticErr.Error())
				}
			}

			assert.Equal(t, test.wantErrors, messages, "JSON diagnostics don't match expected")
		})
	}
}
