package policy

import (
	"testing"
	"strings"
	"os"
	"path/filepath"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name            string
		filename        string
		content         []byte
		wantErr         bool
		wantContains    []string
		wantNotContains []string
		checkConfig     func(t *testing.T, config Config)
	}{
		{
			name:     "decode_and_validation_errors_together",
			filename: "policy.yaml",
			content: []byte(`version: 2
policy:
    length:
        min: 12
        foo: 100
    classes:
      - name: digits
        alphabet: "0123456789"
        min: 2
`),
			wantErr: true,
			wantContains: []string{
				"policy.length.foo",
				"version: must be 1, got 2",
				"policy.name: required",
			},
		},
		{
			name:     "valid_config",
			filename: "policy.yaml",
			content: []byte(`version: 1
policy:
    name: service-accounts
    length:
        min: 12
    classes:
      - name: digits
        alphabet: "0123456789"
        min: 2
`),
			wantErr: false,
			checkConfig: func(t *testing.T, config Config) {
				assert.Equal(t, 1, config.Version)
				assert.Equal(t, "service-accounts", config.Policy.Name)

				assert.Equal(t, 12, config.Policy.Length.Min)
				assert.Equal(t, 12, config.Policy.Length.Max)

				assert.Equal(t, 100, config.Policy.Attempts)

				assert.Equal(t, "0s", config.Issue.History.Ttl)
				assert.Equal(t, "0s", config.Issue.RotateAfter)

				assert.Len(t, config.Policy.Classes, 1)
				assert.Equal(t, "digits", config.Policy.Classes[0].Name)
			},
		},
		{
			name:     "fatal_yaml_syntax_error",
			filename: "policy.yaml",
			content: []byte(`version: 2
policy:
    name: [
`),
			wantErr: true,
			wantContains: []string{
				"decode policy data",
			},
			wantNotContains: []string{
				"version: must be 1",
				"policy.name: required",
				"policy.classes: must not be empty",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			policyPath := filepath.Join(tempDir, test.filename)

			if err := os.WriteFile(policyPath, test.content, 0o600); err != nil {
				t.Fatalf("write policy file: %v", err)
			}

			config, err := LoadConfig(policyPath)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected LoadConfig error, received nil")
				}

				assert.Equal(t, Config{}, config)

				for _, message := range test.wantContains {
					assert.ErrorContains(t, err, message)
				}

				for _, message := range test.wantNotContains {
					assert.NotContains(t, err.Error(), message)
				}

				return
			}

			assert.NoError(t, err)

			if test.checkConfig != nil {
				test.checkConfig(t, config)
			}
		})
	}
}

func TestDecodePolicyData(t *testing.T) {
	tests := []struct {
		name         string
		format       Format
		policy       []byte
		wantContains []string
		wantOrder    []string
	}{
		{
			name:   "yaml_duplicate_key_on_higher_level",
			format: FormatYAML,
			policy: []byte(`version: 1
policy:
    name: first
    name: second`),
			wantContains: []string{
				"line 4",
				"mapping key \"name\" already defined",
			},
		},
		{
			name:   "yaml_duplicate_key_on_deeper_level",
			format: FormatYAML,
			policy: []byte(`version: 1
issue:
    history:
        window: 5
        window: 10`),
			wantContains: []string{
				"line 5",
				"mapping key \"window\" already defined",
			},
		},
		{
			name:   "yaml_unknown_field_nested",
			format: FormatYAML,
			policy: []byte(`version: 1
policy:
    name: test
    length:
        min: 12
        max: 20
        foo: 100`),
			wantContains: []string{
				"field foo not found in type policy.Length",
				"policy.length.foo",
				"line 7",
			},
		},
		{
			name:   "yaml_multiple_unknown_fields",
			format: FormatYAML,
			policy: []byte(`version: 1
policy:
    name: test
    length:
        foo: 1
        bar: 2`),
			wantContains: []string{
				"policy.length.foo",
				"line 5",
				"policy.length.bar",
				"line 6",
			},
			wantOrder: []string{
				"policy.length.foo",
				"policy.length.bar",
			},
		},
		{
			name:   "json_unknown_field_nested",
			format: FormatJSON,
			policy: []byte(`{
				"version": 1,
				"policy": {
					"name": "test",
					"length": {
						"min": 12,
						"max": 20,
						"foo": 100
					}
				}
			}`),
			wantContains: []string{
				"policy.length.foo",
			},
		},
		{
			name:   "json_multiple_unknown_fields",
			format: FormatJSON,
			policy: []byte(`{
				"version": 1,
				"policy": {
					"name": "test",
					"length": {
						"min": 12,
						"max": 20,
						"foo": 100,
						"bar": 20
					}
				}
			}`),
			wantContains: []string{
				"policy.length.foo",
				"policy.length.bar",
			},
			wantOrder: []string{
				"policy.length.foo",
				"policy.length.bar",
			},
		},
		{
			name:   "json_unknown_field_and_type_error",
			format: FormatJSON,
			policy: []byte(`{
				"version": 1,
				"policy": {
					"name": "test",
					"length": {
						"min": "twelve",
						"max": 20,
						"foo": 100
					}
				}
			}`),
			wantContains: []string{
				"policy.length.foo: unknown field",
				"cannot unmarshal string",
				"policy.length.min",
			},
			wantOrder: []string{
				"policy.length.foo: unknown field",
				"cannot unmarshal string",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := decodePolicyData(test.policy, test.format)

			if err == nil {
				t.Fatalf("expected error, received nil")
			}

			for _, er := range test.wantContains {
				assert.ErrorContains(t, err, er)
			}

			stringErr := err.Error()
			lastPosition := 0

			for i, obj := range test.wantOrder {
				currentPosition := strings.Index(stringErr, obj)
				if currentPosition < 0 {
					t.Fatalf("line: %q doesn't exist", obj)
				}
				if i == 0 {
					lastPosition = currentPosition
					continue
				}
				if currentPosition <= lastPosition {
					t.Fatal("incorrect position")
				}
				lastPosition = currentPosition
			}
		})
	}
}
