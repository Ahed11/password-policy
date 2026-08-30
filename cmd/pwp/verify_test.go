package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/history"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunVerifyHealthyStore(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	store, err := history.Open(storePath)
	require.NoError(t, err)

	record := verifyCLIRecord("svc-01", 1, time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC))

	require.NoError(t, store.Save(record))
	require.NoError(t, store.Close())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"verify",
			"--store",
			storePath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(
		t,
		`{
  "checked": 1,
  "issues": []
}
`,
		stdout.String(),
	)

	assert.Empty(t, stderr.String())
}

func TestRunVerifyEmptyStore(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(
		context.Background(),
		[]string{
			"--store",
			storePath,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(
		t,
		`{
  "checked": 0,
  "issues": []
}
`,
		stdout.String(),
	)

	assert.Empty(t, stderr.String())
}

func TestRunVerifyIssuesReturnFailure(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	store, err := history.Open(storePath)
	require.NoError(t, err)

	record := verifyCLIRecord("svc-01", 1, time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC))

	record.Hash = []byte{1, 2, 3}

	require.NoError(t, store.Save(record))
	require.NoError(t, store.Close())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(
		context.Background(),
		[]string{
			"--store",
			storePath,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.Equal(
		t,
		`{
  "checked": 1,
  "issues": [
    {
      "key": "0000000000000001",
      "subject": "svc-01",
      "message": "invalid hash length: got 3 bytes, want 32"
    }
  ]
}
`,
		stdout.String(),
	)

	assert.Empty(t, stderr.String())
}

func TestRunVerifyDoesNotExposeRecordSecrets(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	store, err := history.Open(storePath)
	require.NoError(t, err)

	record := verifyCLIRecord("svc-01", 1, time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC))

	record.Hash = []byte{1}

	require.NoError(t, store.Save(record))
	require.NoError(t, store.Close())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(
		context.Background(),
		[]string{
			"--store",
			storePath,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.NotContains(t, stdout.String(), string(record.Salt))

	assert.NotContains(t, stdout.String(), string(record.Hash))

	assert.Empty(t, stderr.String())
}

func TestRunVerifyHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(
		context.Background(),
		[]string{"--help"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "Usage:")

	assert.Contains(t, stdout.String(), "pwp verify --store <dir>")

	assert.Empty(t, stderr.String())
}

func TestRunVerifyMissingStore(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(context.Background(), nil, &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp verify: --store is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunVerifyUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(
		context.Background(),
		[]string{"--unknown"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp verify:")

	assert.Contains(t, stderr.String(), "flag provided but not defined")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunVerifyUnexpectedArgument(t *testing.T) {
	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(
		context.Background(),
		[]string{
			"--store",
			t.TempDir(),
			secretArgument,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp verify: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunVerifyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runVerify(
		ctx,
		[]string{
			"--store",
			t.TempDir(),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp verify: context canceled")
}

func TestRunVerifyStdoutWriteError(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	writeErr := errors.New("forced write error")

	var stderr bytes.Buffer

	code := runVerify(
		context.Background(),
		[]string{
			"--store",
			storePath,
		},
		verifyErrorWriter{
			err: writeErr,
		},
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "pwp verify: write stdout: forced write error")
}

func TestWriteVerifyOutputShortWrite(t *testing.T) {
	err := writeVerifyOutput(verifyShortWriter{}, []byte("verify result"))

	assert.ErrorIs(t, err, io.ErrShortWrite)
}

func verifyCLIRecord(subject string, number byte, issuedAt time.Time) history.Record {
	salt := make([]byte, history.SaltSize)

	for i := range salt {
		salt[i] = number + byte(i)
	}

	hash := make([]byte, sha256.Size)

	for i := range hash {
		hash[i] = number + byte(i)
	}

	issuedAt = issuedAt.UTC()

	return history.Record{
		Subject: subject,
		Salt:    salt,
		Hash:    hash,

		IssuedAt: issuedAt,

		ExpiresAt: issuedAt.Add(24 * time.Hour),

		PolicyName:    "verify-test",
		PolicyVersion: "version-1",
	}
}

type verifyErrorWriter struct {
	err error
}

func (w verifyErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

type verifyShortWriter struct{}

func (verifyShortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	return len(data) - 1, nil
}
