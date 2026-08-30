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

func TestRunEntropySuccess(t *testing.T) {
	policyPath := writeEntropyTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"entropy", "--policy", policyPath}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "1.0 bits (lower bound)\n", stdout.String())

	assert.Empty(t, stderr.String())
}

func TestRunEntropyHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runEntropy(context.Background(), []string{"--help"}, &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "Usage:")
	assert.Contains(t, stdout.String(), "pwp entropy --policy <file>")

	assert.Empty(t, stderr.String())
}

func TestRunEntropyMissingPolicy(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runEntropy(context.Background(), nil, &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp entropy: --policy is required")
	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunEntropyUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runEntropy(context.Background(), []string{"--unknown"}, &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp entropy:")
	assert.Contains(t, stderr.String(), "flag provided but not defined")
	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunEntropyUnexpectedArgument(t *testing.T) {
	policyPath := writeEntropyTestPolicy(t)

	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runEntropy(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			secretArgument,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp entropy: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunEntropyMissingPolicyFile(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "missing.yaml")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runEntropy(context.Background(), []string{"--policy", policyPath}, &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp entropy:")
	assert.Contains(t, stderr.String(), "missing.yaml")
}

func TestRunEntropyInvalidPolicy(t *testing.T) {
	tempDir := t.TempDir()

	policyPath := filepath.Join(tempDir, "invalid.yaml")

	err := os.WriteFile(
		policyPath,
		[]byte(`version: 1
policy:
  name: [
`),
		0o600,
	)
	require.NoError(t, err)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runEntropy(context.Background(), []string{"--policy", policyPath}, &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp entropy:")
	assert.Contains(t, stderr.String(), "decode policy data")
}

func TestRunEntropyCanceledContext(t *testing.T) {
	policyPath := writeEntropyTestPolicy(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runEntropy(ctx, []string{"--policy", policyPath}, &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp entropy: context canceled")
}

func writeEntropyTestPolicy(t *testing.T) string {
	t.Helper()

	tempDir := t.TempDir()

	policyPath := filepath.Join(tempDir, "policy.yaml")

	err := os.WriteFile(
		policyPath,
		[]byte(`version: 1
policy:
  name: entropy-test
  length:
    min: 1
    max: 1
  classes:
    - name: symbols
      alphabet: "ab"
      min: 0
  attempts: 1
`),
		0o600,
	)
	require.NoError(t, err)

	return policyPath
}
