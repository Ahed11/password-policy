package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/history"
	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunIssueSuccess(t *testing.T) {
	policyPath := writeIssueTestPolicy(t)

	storePath := filepath.Join(t.TempDir(), "history")

	const nowValue = "2026-08-29T18:00:00Z"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"issue",
			"--policy",
			policyPath,
			"--subject",
			"svc-01",
			"--store",
			storePath,
			"--now",
			nowValue,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)
	assert.Empty(t, stderr.String())

	output := stdout.Bytes()

	require.NotEmpty(t, output)
	require.Equal(t, byte('\n'), output[len(output)-1])

	password := output[:len(output)-1]
	defer secret.Zero(password)

	require.Equal(t, 2, len(password))

	store, err := history.Open(storePath)
	require.NoError(t, err)

	metadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, 2, metadata.HistoryWindow)
	assert.Equal(t, 180*24*time.Hour, metadata.HistoryTTL)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	require.Len(t, records, 1)

	record := records[0]

	expectedIssuedAt, err := time.Parse(time.RFC3339, nowValue)
	require.NoError(t, err)

	assert.Equal(t, "svc-01", record.Subject)
	assert.Equal(t, "issue-test", record.PolicyName)

	assert.Equal(t, expectedIssuedAt.UTC(), record.IssuedAt)

	assert.Equal(t, expectedIssuedAt.Add(90*24*time.Hour).UTC(), record.ExpiresAt)

	require.Len(t, record.Salt, history.SaltSize)
	require.Len(t, record.Hash, 32)

	assert.True(t, history.Matches(record, password))

	require.NotEmpty(t, record.PolicyVersion)

	decodedVersion, err := hex.DecodeString(record.PolicyVersion)
	require.NoError(t, err)

	assert.Len(t, decodedVersion, 32)

	require.NoError(t, store.Close())
}

func TestRunIssueWritesOutputFile(t *testing.T) {
	policyPath := writeIssueTestPolicy(t)

	tempDir := t.TempDir()

	storePath := filepath.Join(tempDir, "history")
	outputPath := filepath.Join(tempDir, "password.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--subject",
			"svc-file",
			"--store",
			storePath,
			"--out",
			outputPath,
			"--now",
			"2026-08-29T18:00:00Z",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	defer secret.Zero(data)

	require.Len(t, data, 3)

	assert.Equal(t, byte('\n'), data[len(data)-1])
}

func TestRunIssueHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{"--help"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "Usage:")
	assert.Contains(t, stdout.String(), "pwp issue --policy <file> --subject <subject>")

	assert.Empty(t, stderr.String())
}

func TestRunIssueMissingPolicy(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{
			"--subject",
			"svc-01",
			"--store",
			t.TempDir(),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp issue: --policy is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunIssueMissingSubject(t *testing.T) {
	policyPath := writeIssueTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--store",
			t.TempDir(),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp issue: --subject is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunIssueMissingStore(t *testing.T) {
	policyPath := writeIssueTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--subject",
			"svc-01",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp issue: --store is required when issue.store is empty")
}

func TestRunIssueUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{"--unknown"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp issue:")
	assert.Contains(t, stderr.String(), "flag provided but not defined")
	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunIssueUnexpectedArgument(t *testing.T) {
	policyPath := writeIssueTestPolicy(t)

	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--subject",
			"svc-01",
			"--store",
			t.TempDir(),
			secretArgument,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp issue: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunIssueMissingPolicyFile(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "missing.yaml")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--subject",
			"svc-01",
			"--store",
			t.TempDir(),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp issue:")
	assert.Contains(t, stderr.String(), "missing.yaml")
}

func TestRunIssueInvalidNow(t *testing.T) {
	policyPath := writeIssueTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--subject",
			"svc-01",
			"--store",
			t.TempDir(),
			"--now",
			"not-a-time",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), `pwp issue: invalid --now value "not-a-time"`)
}

func TestRunIssueCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runIssue(
		ctx,
		[]string{
			"--policy",
			"unused.yaml",
			"--subject",
			"svc-01",
			"--store",
			t.TempDir(),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp issue: context canceled")
}

func TestParseIssueDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:  "zero seconds",
			input: "0s",
			want:  0,
		},
		{
			name:  "seconds",
			input: "30s",
			want:  30 * time.Second,
		},
		{
			name:  "minutes",
			input: "15m",
			want:  15 * time.Minute,
		},
		{
			name:  "hours",
			input: "12h",
			want:  12 * time.Hour,
		},
		{
			name:  "days",
			input: "3d",
			want:  72 * time.Hour,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing suffix",
			input:   "10",
			wantErr: true,
		},
		{
			name:    "negative",
			input:   "-1h",
			wantErr: true,
		},
		{
			name:    "unknown suffix",
			input:   "10w",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				got, err := parseIssueDuration(test.input)

				if test.wantErr {
					require.Error(t, err)

					return
				}

				require.NoError(t, err)

				assert.Equal(t, test.want, got)
			},
		)
	}
}

func writeIssueTestPolicy(t *testing.T) string {
	t.Helper()

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")

	data := []byte(`version: 1
policy:
  name: issue-test
  length:
    min: 2
    max: 2
  classes:
    - name: all
      alphabet: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      min: 0
  attempts: 10
issue:
  history:
    window: 2
    ttl: 180d
  rotate_after: 90d
`)

	err := os.WriteFile(policyPath, data, 0o600)
	require.NoError(t, err)

	return policyPath
}
