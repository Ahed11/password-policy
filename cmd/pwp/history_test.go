package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/history"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunHistorySuccess(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	olderIssuedAt := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	newerIssuedAt := time.Date(2026, time.August, 29, 18, 0, 0, 0, time.UTC)

	store, err := history.Open(storePath)
	require.NoError(t, err)

	err = store.Save(
		history.Record{
			Subject:       "svc-01",
			Salt:          []byte("newer-secret-salt"),
			Hash:          []byte("newer-secret-hash"),
			IssuedAt:      newerIssuedAt,
			ExpiresAt:     newerIssuedAt.Add(90 * 24 * time.Hour),
			PolicyName:    "policy-b",
			PolicyVersion: "version-b",
		},
	)
	require.NoError(t, err)

	err = store.Save(
		history.Record{
			Subject:       "svc-02",
			Salt:          []byte("other-secret-salt"),
			Hash:          []byte("other-secret-hash"),
			IssuedAt:      olderIssuedAt,
			ExpiresAt:     olderIssuedAt.Add(90 * 24 * time.Hour),
			PolicyName:    "other-policy",
			PolicyVersion: "other-version",
		},
	)
	require.NoError(t, err)

	err = store.Save(
		history.Record{
			Subject:       "svc-01",
			Salt:          []byte("older-secret-salt"),
			Hash:          []byte("older-secret-hash"),
			IssuedAt:      olderIssuedAt,
			ExpiresAt:     olderIssuedAt.Add(90 * 24 * time.Hour),
			PolicyName:    "policy-a",
			PolicyVersion: "version-a",
		},
	)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"history",
			"--subject",
			"svc-01",
			"--store",
			storePath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)
	assert.Empty(t, stderr.String())

	expected := `[
  {
    "subject": "svc-01",
    "issued_at": "2026-08-28T12:00:00Z",
    "expires_at": "2026-11-26T12:00:00Z",
    "policy_name": "policy-a",
    "policy_version": "version-a"
  },
  {
    "subject": "svc-01",
    "issued_at": "2026-08-29T18:00:00Z",
    "expires_at": "2026-11-27T18:00:00Z",
    "policy_name": "policy-b",
    "policy_version": "version-b"
  }
]
`

	assert.Equal(t, expected, stdout.String())

	assert.NotContains(t, stdout.String(), `"salt"`)
	assert.NotContains(t, stdout.String(), `"hash"`)

	assert.NotContains(t, stdout.String(), "svc-02")
	assert.NotContains(t, stdout.String(), "other-policy")
}

func TestRunHistoryEmpty(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runHistory(
		context.Background(),
		[]string{
			"--subject",
			"svc-01",
			"--store",
			storePath,
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "[]\n", stdout.String())

	assert.Empty(t, stderr.String())
}

func TestRunHistoryHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runHistory(
		context.Background(),
		[]string{"--help"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "Usage:")
	assert.Contains(t, stdout.String(), "pwp history --subject <subject> --store <dir>")

	assert.Empty(t, stderr.String())
}

func TestRunHistoryMissingSubject(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runHistory(
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

	assert.Contains(t, stderr.String(), "pwp history: --subject is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunHistoryMissingStore(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runHistory(
		context.Background(),
		[]string{
			"--subject",
			"svc-01",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp history: --store is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunHistoryUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runHistory(
		context.Background(),
		[]string{"--unknown"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp history:")
	assert.Contains(t, stderr.String(), "flag provided but not defined")
	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunHistoryUnexpectedArgument(t *testing.T) {
	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runHistory(
		context.Background(),
		[]string{
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

	assert.Contains(t, stderr.String(), "pwp history: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunHistoryCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runHistory(
		ctx,
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

	assert.Contains(t, stderr.String(), "pwp history: context canceled")
}

func TestRunHistoryStdoutWriteError(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	writeErr := errors.New("forced write error")

	var stderr bytes.Buffer

	code := runHistory(
		context.Background(),
		[]string{
			"--subject",
			"svc-01",
			"--store",
			storePath,
		},
		historyErrorWriter{
			err: writeErr,
		},
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "pwp history: write stdout: forced write error")
}

func TestMarshalHistoryRecordsEmpty(t *testing.T) {
	data, err := marshalHistoryRecords(nil)
	require.NoError(t, err)

	assert.Equal(t, "[]\n", string(data))
}

func TestWriteHistoryOutputShortWrite(t *testing.T) {
	err := writeHistoryOutput(historyShortWriter{}, []byte("history"))

	assert.ErrorIs(t, err, io.ErrShortWrite)
}

type historyErrorWriter struct {
	err error
}

func (w historyErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

type historyShortWriter struct{}

func (historyShortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	return len(data) - 1, nil
}
