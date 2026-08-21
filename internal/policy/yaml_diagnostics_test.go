package policy

import (
	"fmt"

	"testing"

	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
)

func TestYAMLErrorLines(t *testing.T) {
	tests := []struct{
		name string
		err error
		want []errorLine
	}{
		{
			name: "one_error_with_line",
			err: &yaml.TypeError{
				Errors: []string{
					"line 8: field foo not found in type policy.Length",
				},
			},
			want: []errorLine{
				{
					line:    8,
					message: "line 8: field foo not found in type policy.Length",
				},
			},
		},
		{
			name: "multiple_errors_with_lines",
			err: &yaml.TypeError{
				Errors: []string{
					"line 8: field foo not found in type policy.Length",
					"line 10: field bar not found in type policy.Length",
				},
			},
			want: []errorLine{
				{
					line: 8,
					message: "line 8: field foo not found in type policy.Length",
				},
				{
					line: 10,
					message: "line 10: field bar not found in type policy.Length",
				},
			},
		},
		{
			name: "error_without_line",
			err: &yaml.TypeError{
				Errors: []string{
					"some yaml problem",
				},
			},
			want: []errorLine{
				{
					line: 0,
					message: "some yaml problem",
				},
			},
		},
		{
			name: "not_yaml_type_error",
			err: fmt.Errorf("ordinary error"),
			want: nil,
		},
		{
			name: "wrapped_yaml_type_error",
			err: fmt.Errorf(
				"decode policy: %w",
				&yaml.TypeError{
					Errors: []string{
						"line 12: field bad not found",
					},
				},
			),
			want: []errorLine{
				{
					line:    12,
					message: "line 12: field bad not found",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := yamlErrorLines(test.err)

			assert.Equal(t, test.want, got)
		})
	}
}

func TestFindYAMLPathByLine(t *testing.T) {
	tests := []struct{
		name string
		policy []byte
		line int
		wantFound bool
		wantPath string
	}{
		{
			name: "unknown_field_1",
			policy: []byte(`
version: 1
policy:
    length:
        min: 12
        foo: 100`),
		line: 6,
		wantFound: true,
		wantPath: "policy.length.foo",
		},
		{
			name: "unknown_field_2",
			policy: []byte(`
version: 1
policy:
    classes:
      - name: digits
        foo: 100`),
		line: 6,
		wantFound: true,
		wantPath: "policy.classes[0].foo",
		},
		{
			name: "unknown_field_2",
			policy: []byte(`
version: 1
policy:
    classes:
      - name: digits
        foo: 100`),
		line: 999,
		wantFound: false,
		wantPath: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var root yaml.Node

			if nodeErr := yaml.Unmarshal(test.policy, &root); nodeErr != nil {
				t.Fatalf("unexpected YAML unmarshal error: %v", nodeErr)
			}

			fieldPath, found := findYAMLPathByLine(&root, test.line)

			assert.Equal(t, test.wantFound, found)
			assert.Equal(t, test.wantPath, fieldPath)
		})
	}
}