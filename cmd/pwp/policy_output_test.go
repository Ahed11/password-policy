package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWritePolicyValidationResultDefaults(t *testing.T) {
	cfg := loadPolicyOutputTestConfig(
		t,
		`
version: 1
policy:
  name: test-policy
  classes:
    - name: letters
      alphabet: "abcdefghijklmnopqrstuvwxyz"
`,
	)

	var output bytes.Buffer

	err := writePolicyValidationResult(&output, cfg)
	require.NoError(t, err)

	var decoded policyValidationOutput

	err = json.Unmarshal(output.Bytes(), &decoded)
	require.NoError(t, err)

	assert.Equal(t, "policy is valid", decoded.Status)

	assert.Equal(t, 1, decoded.Version)

	assert.Equal(t, "test-policy", decoded.Policy.Name)

	assert.Equal(t, 12, decoded.Policy.Length.Min)

	assert.Equal(t, 12, decoded.Policy.Length.Max)

	require.Len(t, decoded.Policy.Classes, 1)

	assert.Equal(t, "letters", decoded.Policy.Classes[0].Name)

	assert.Equal(t, "abcdefghijklmnopqrstuvwxyz", decoded.Policy.Classes[0].Alphabet)

	assert.Equal(t, 0, decoded.Policy.Classes[0].Min)

	assert.Equal(t, "", decoded.Policy.Exclude)

	assert.Equal(t, 100, decoded.Policy.Attempts)

	assert.Equal(t, 0, decoded.Policy.Forbid.RepeatRun)

	assert.False(t, decoded.Policy.Forbid.RepeatTotal)

	assert.Equal(t, 0, decoded.Policy.Forbid.Sequences.Alphabet)

	assert.Equal(t, 0, decoded.Policy.Forbid.Sequences.Keyboard)

	assert.Equal(t, []string{"qwerty"}, decoded.Policy.Forbid.Sequences.Layouts)

	assert.Equal(t, "", decoded.Policy.Forbid.Dictionary.Path)

	assert.Equal(t, 4, decoded.Policy.Forbid.Dictionary.MinLength)

	assert.True(t, decoded.Policy.Forbid.Dictionary.CaseInsensitive)

	assert.False(t, decoded.Policy.Forbid.Dictionary.Leet)

	assert.Equal(t, 3, decoded.Policy.Forbid.Context.MinLength)

	assert.Equal(t, 16, decoded.Issue.PoolSize)

	assert.Equal(t, "", decoded.Issue.Store)

	assert.Equal(t, 0, decoded.Issue.History.Window)

	assert.Equal(t, "0s", decoded.Issue.History.Ttl)

	assert.Equal(t, "0s", decoded.Issue.RotateAfter)
}

func TestWritePolicyValidationResultExplicitValues(t *testing.T) {
	cfg := loadPolicyOutputTestConfig(
		t,
		`
version: 1
policy:
  name: custom-policy
  length:
    min: 16
    max: 20
  classes:
    - name: lower
      alphabet: "abcdef"
      min: 2
    - name: digits
      alphabet: "0123456789"
      min: 1
  exclude: "x"
  attempts: 7
  forbid:
    repeat_run: 3
    repeat_total: true
    sequences:
      alphabet: 4
      keyboard: 5
      layouts:
        - qwerty
        - dvorak
    dictionary:
      path: ""
      min_length: 6
      case_insensitive: false
      leet: true
    context:
      min_length: 5

issue:
  pool_size: 4
  store: "history"
  history:
    window: 6
    ttl: "30d"
  rotate_after: "12h"
`,
	)

	var output bytes.Buffer

	err := writePolicyValidationResult(&output, cfg)
	require.NoError(t, err)

	var decoded policyValidationOutput

	err = json.Unmarshal(output.Bytes(), &decoded)
	require.NoError(t, err)

	assert.Equal(t, "policy is valid", decoded.Status)

	assert.Equal(t, cfg.Version, decoded.Version)

	assert.Equal(t, cfg.Policy, decoded.Policy)

	assert.Equal(t, cfg.Issue, decoded.Issue)

	require.Len(t, decoded.Policy.Classes, 2)

	assert.Equal(t, "lower", decoded.Policy.Classes[0].Name)

	assert.Equal(t, "digits", decoded.Policy.Classes[1].Name)

	assert.Equal(t, 16, decoded.Policy.Length.Min)

	assert.Equal(t, 20, decoded.Policy.Length.Max)

	assert.Equal(t, 7, decoded.Policy.Attempts)

	assert.Equal(t, 6, decoded.Issue.History.Window)

	assert.Equal(t, "30d", decoded.Issue.History.Ttl)

	assert.Equal(t, "12h", decoded.Issue.RotateAfter)
}

func TestWritePolicyValidationResultDeterministic(t *testing.T) {
	cfg := loadPolicyOutputTestConfig(
		t,
		`
version: 1
policy:
  name: deterministic-policy
  classes:
    - name: first
      alphabet: "abcdef"
    - name: second
      alphabet: "0123456789"
`,
	)

	var first bytes.Buffer
	var second bytes.Buffer

	err := writePolicyValidationResult(&first, cfg)
	require.NoError(t, err)

	err = writePolicyValidationResult(&second, cfg)
	require.NoError(t, err)

	assert.Equal(t, first.Bytes(), second.Bytes())

	assert.NotEmpty(t, first.Bytes())
}

func TestWritePolicyValidationResultIsValidJSON(t *testing.T) {
	cfg := loadPolicyOutputTestConfig(
		t,
		`
version: 1
policy:
  name: json-policy
  classes:
    - name: letters
      alphabet: "abcdefghijklmnopqrstuvwxyz"
`,
	)

	var output bytes.Buffer

	err := writePolicyValidationResult(&output, cfg)
	require.NoError(t, err)

	assert.True(t, json.Valid(output.Bytes()))
}

func TestWritePolicyValidationResultContainsStatus(t *testing.T) {
	cfg := loadPolicyOutputTestConfig(
		t,
		`
version: 1
policy:
  name: test-policy
  classes:
    - name: letters
      alphabet: "abcdefghijklmnopqrstuvwxyz"
`,
	)

	var output bytes.Buffer

	err := writePolicyValidationResult(&output, cfg)
	require.NoError(t, err)

	assert.Contains(t, output.String(), `"status": "policy is valid"`)
}

func TestWritePolicyValidationResultEndsWithNewline(t *testing.T) {
	cfg := loadPolicyOutputTestConfig(
		t,
		`
version: 1
policy:
  name: test-policy
  classes:
    - name: letters
      alphabet: "abcdefghijklmnopqrstuvwxyz"
`,
	)

	var output bytes.Buffer

	err := writePolicyValidationResult(&output, cfg)
	require.NoError(t, err)

	assert.True(t, bytes.HasSuffix(output.Bytes(), []byte("\n")))
}

func TestWritePolicyValidationResultNilWriter(t *testing.T) {
	cfg := policy.Config{
		Version: 1,
	}

	err := writePolicyValidationResult(nil, cfg)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "writer must not be nil")
}

func loadPolicyOutputTestConfig(t *testing.T, content string) policy.Config {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")

	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)

	cfg, err := policy.LoadConfig(path)
	require.NoError(t, err)

	return cfg
}
