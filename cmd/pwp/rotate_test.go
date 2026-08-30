package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/history"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunRotateGoldenPlan(t *testing.T) {
	policyPath := filepath.Join("..", "..", "testdata", "golden", "policy.yaml")

	storePath := filepath.Join(t.TempDir(), "history")

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-01",
			Salt:          []byte("salt-01"),
			Hash:          []byte("hash-01"),
			IssuedAt:      time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2026, time.October, 30, 0, 0, 0, 0, time.UTC),
			PolicyName:    "demo-service-accounts",
			PolicyVersion: "golden-version",
		},
	)

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-02",
			Salt:          []byte("salt-02"),
			Hash:          []byte("hash-02"),
			IssuedAt:      time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2026, time.December, 30, 0, 0, 0, 0, time.UTC),
			PolicyName:    "demo-service-accounts",
			PolicyVersion: "golden-version",
		},
	)

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-03",
			Salt:          []byte("salt-03"),
			Hash:          []byte("hash-03"),
			IssuedAt:      time.Date(2026, time.August, 15, 0, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2026, time.November, 13, 0, 0, 0, 0, time.UTC),
			PolicyName:    "demo-service-accounts",
			PolicyVersion: "golden-version",
		},
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--store",
			storePath,
			"--now",
			"2026-12-01T00:00:00Z",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)
	assert.Empty(t, stderr.String())

	expected, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "rotation_plan.json"))
	require.NoError(t, err)

	actual := bytes.ReplaceAll(stdout.Bytes(), []byte("\r\n"), []byte("\n"))

	expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))

	assert.Equal(t, string(expected), string(actual))
}

func TestRunRotateEmptyPlan(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)
	storePath := filepath.Join(t.TempDir(), "history")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"rotate",
			"--policy",
			policyPath,
			"--store",
			storePath,
			"--now",
			"2026-08-29T18:00:00Z",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(
		t,
		`{
  "items": [],
  "warnings": []
}
`,
		stdout.String(),
	)

	assert.Empty(t, stderr.String())
}

func TestRunRotateDueReturnsFailure(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)
	storePath := filepath.Join(t.TempDir(), "history")

	issuedAt := time.Date(2026, time.August, 27, 18, 0, 0, 0, time.UTC)

	expiresAt := time.Date(2026, time.August, 28, 18, 0, 0, 0, time.UTC)

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-01",
			Salt:          []byte("rotation-secret-salt"),
			Hash:          []byte("rotation-secret-hash"),
			IssuedAt:      issuedAt,
			ExpiresAt:     expiresAt,
			PolicyName:    "rotate-test",
			PolicyVersion: "version-1",
		},
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--store",
			storePath,
			"--now",
			"2026-08-29T18:00:00Z",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.Equal(
		t,
		`{
  "items": [
    {
      "subject": "svc-01",
      "issued_at": "2026-08-27T18:00:00Z",
      "expires_at": "2026-08-28T18:00:00Z",
      "reason": "expired"
    }
  ],
  "warnings": []
}
`,
		stdout.String(),
	)

	assert.Empty(t, stderr.String())

	assert.NotContains(t, stdout.String(), "rotation-secret-salt")

	assert.NotContains(t, stdout.String(), "rotation-secret-hash")
}

func TestRunRotateClockMovedBackwardWarning(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)
	storePath := filepath.Join(t.TempDir(), "history")

	now := time.Date(2026, time.August, 29, 18, 0, 0, 0, time.UTC)

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-01",
			Salt:          []byte("salt"),
			Hash:          []byte("hash"),
			IssuedAt:      now.Add(time.Hour),
			ExpiresAt:     now.Add(2 * time.Hour),
			PolicyName:    "rotate-test",
			PolicyVersion: "version-1",
		},
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--store",
			storePath,
			"--now",
			now.Format(time.RFC3339),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Empty(t, stderr.String())

	assert.Contains(t, stdout.String(), `"items": []`)

	assert.Contains(t, stdout.String(), "clock moved backwards")

	assert.Contains(t, stdout.String(), "svc-01")
}

func TestRunRotateStrictWarningReturnsUsage(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)
	storePath := filepath.Join(t.TempDir(), "history")

	now := time.Date(2026, time.August, 29, 18, 0, 0, 0, time.UTC)

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-01",
			Salt:          []byte("salt"),
			Hash:          []byte("hash"),
			IssuedAt:      now.Add(time.Hour),
			ExpiresAt:     now.Add(2 * time.Hour),
			PolicyName:    "rotate-test",
			PolicyVersion: "version-1",
		},
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--store",
			storePath,
			"--now",
			now.Format(time.RFC3339),
			"--strict",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stderr.String())

	assert.Contains(t, stdout.String(), "clock moved backwards")
}

func TestRunRotateDeterministic(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)
	storePath := filepath.Join(t.TempDir(), "history")

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-b",
			Salt:          []byte("salt-b"),
			Hash:          []byte("hash-b"),
			IssuedAt:      time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC),
			PolicyName:    "rotate-test",
			PolicyVersion: "version-b",
		},
	)

	saveRotateTestRecord(
		t,
		storePath,
		history.Record{
			Subject:       "svc-a",
			Salt:          []byte("salt-a"),
			Hash:          []byte("hash-a"),
			IssuedAt:      time.Date(2026, time.August, 27, 13, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2026, time.August, 28, 13, 0, 0, 0, time.UTC),
			PolicyName:    "rotate-test",
			PolicyVersion: "version-a",
		},
	)

	args := []string{
		"--policy",
		policyPath,
		"--store",
		storePath,
		"--now",
		"2026-08-29T18:00:00Z",
	}

	var firstStdout bytes.Buffer
	var firstStderr bytes.Buffer

	firstCode := runRotate(context.Background(), args, &firstStdout, &firstStderr)

	var secondStdout bytes.Buffer
	var secondStderr bytes.Buffer

	secondCode := runRotate(context.Background(), args, &secondStdout, &secondStderr)

	assert.Equal(t, exitFailure, firstCode)
	assert.Equal(t, exitFailure, secondCode)

	assert.Equal(t, firstStdout.String(), secondStdout.String())

	assert.Empty(t, firstStderr.String())
	assert.Empty(t, secondStderr.String())
}

func TestRunRotateHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(context.Background(), []string{"--help"}, &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "Usage:")

	assert.Contains(t, stdout.String(), "pwp rotate --policy <file>")

	assert.Empty(t, stderr.String())
}

func TestRunRotateMissingPolicy(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--store",
			t.TempDir(),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp rotate: --policy is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunRotateMissingStore(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp rotate: --store is required when issue.store is empty")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunRotateInvalidNow(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
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

	assert.Contains(t, stderr.String(), `pwp rotate: invalid --now value "not-a-time"`)
}

func TestRunRotateUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{"--unknown"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp rotate:")

	assert.Contains(t, stderr.String(), "flag provided but not defined")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunRotateUnexpectedArgument(t *testing.T) {
	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			"unused.yaml",
			"--store",
			t.TempDir(),
			secretArgument,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp rotate: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunRotateCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runRotate(
		ctx,
		[]string{
			"--policy",
			"unused.yaml",
			"--store",
			t.TempDir(),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp rotate: context canceled")
}

func TestRunRotateStdoutWriteError(t *testing.T) {
	policyPath := writeRotateTestPolicy(t)
	storePath := filepath.Join(t.TempDir(), "history")

	writeErr := errors.New("forced write error")

	var stderr bytes.Buffer

	code := runRotate(
		context.Background(),
		[]string{
			"--policy",
			policyPath,
			"--store",
			storePath,
			"--now",
			"2026-08-29T18:00:00Z",
		},
		rotateErrorWriter{
			err: writeErr,
		},
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "pwp rotate: write stdout: forced write error")
}

func TestWriteRotationPlanShortWrite(t *testing.T) {
	err := writeRotationPlan(rotateShortWriter{}, []byte("rotation plan"))

	assert.ErrorIs(t, err, io.ErrShortWrite)
}

func writeRotateTestPolicy(t *testing.T) string {
	t.Helper()

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")

	data := []byte(`version: 1
policy:
  name: rotate-test
  length:
    min: 1
    max: 1
  classes:
    - name: symbols
      alphabet: "ab"
      min: 0
`)

	err := os.WriteFile(policyPath, data, 0o600)
	require.NoError(t, err)

	return policyPath
}

func saveRotateTestRecord(t *testing.T, storePath string, record history.Record) {
	t.Helper()

	store, err := history.Open(storePath)
	require.NoError(t, err)

	require.NoError(t, store.Save(record))

	require.NoError(t, store.Close())
}

type rotateErrorWriter struct {
	err error
}

func (w rotateErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

type rotateShortWriter struct{}

func (rotateShortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	return len(data) - 1, nil
}
