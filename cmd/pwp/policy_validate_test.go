package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyValidateYAML(t *testing.T) {
	path := writePolicyValidateTestFile(
		t,
		"policy.yaml",
		`
version: 1
policy:
  name: test-policy
  length:
    min: 12
    max: 12
  classes:
    - name: letters
      alphabet: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      min: 1
`,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--policy", path}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "policy is valid")

	assert.Empty(t, stderr.String())
}

func TestPolicyValidateJSON(t *testing.T) {
	path := writePolicyValidateTestFile(
		t,
		"policy.json",
		`{
  "version": 1,
  "policy": {
    "name": "test-policy",
    "length": {
      "min": 12,
      "max": 12
    },
    "classes": [
      {
        "name": "letters",
        "alphabet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "min": 1
      }
    ]
  }
}`,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--policy", path}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "policy is valid")

	assert.Empty(t, stderr.String())
}

func TestPolicyValidateMissingPolicyFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "--policy is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestPolicyValidateMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--policy", path}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp policy validate:")
}

func TestPolicyValidateInvalidVersion(t *testing.T) {
	path := writePolicyValidateTestFile(
		t,
		"invalid-version.yaml",
		`
version: 2
policy:
  name: test-policy
  classes:
    - name: letters
      alphabet: "abcdefghijklmnopqrstuvwxyz"
`,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--policy", path}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "version")
}

func TestPolicyValidateInvalidAlphabetIntersection(t *testing.T) {
	path := writePolicyValidateTestFile(
		t,
		"intersection.yaml",
		`
version: 1
policy:
  name: test-policy
  length:
    min: 12
    max: 12
  classes:
    - name: first
      alphabet: "abcdef"
    - name: second
      alphabet: "fghijk"
`,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--policy", path}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.NotEmpty(t, stderr.String())
}

func TestPolicyValidateInvalidSyntax(t *testing.T) {
	path := writePolicyValidateTestFile(
		t,
		"invalid.yaml",
		`
version: 1
policy:
  name: test-policy
  classes:
    - name: letters
      alphabet: [
`,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--policy", path}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.NotEmpty(t, stderr.String())
}

func TestPolicyValidateUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--unknown"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "unknown")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestPolicyValidateUnexpectedArgument(t *testing.T) {
	path := writePolicyValidateTestFile(
		t,
		"policy.yaml",
		`
version: 1
policy:
  name: test-policy
  classes:
    - name: letters
      alphabet: "abcdefghijklmnopqrstuvwxyz"
`,
	)

	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "validate", "--policy", path, secretArgument}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp policy validate: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)
}

func TestPolicyValidateHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "short help",
			args: []string{
				"policy",
				"validate",
				"-h",
			},
		},
		{
			name: "long help",
			args: []string{
				"policy",
				"validate",
				"--help",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(context.Background(), tt.args, bytes.NewReader(nil), &stdout, &stderr)

			assert.Equal(t, exitSuccess, code)

			assert.Contains(t, stdout.String(), "pwp policy validate --policy <file>")

			assert.Empty(t, stderr.String())
		},
		)
	}
}

func TestPolicyHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "--help"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "pwp policy <command>")

	assert.Contains(t, stdout.String(), "validate")

	assert.Empty(t, stderr.String())
}

func TestPolicyWithoutSubcommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp policy <command>")
}

func TestPolicyUnknownSubcommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"policy", "unknown"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), `unknown command "unknown"`)
}

func writePolicyValidateTestFile(t *testing.T, name string, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)

	return path
}
