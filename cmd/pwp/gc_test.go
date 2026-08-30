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

func TestRunGCSuccess(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)

	expired := gcCLIRecord("svc-01", 1, now.Add(-72*time.Hour))

	protected := gcCLIRecord("svc-01", 2, now.Add(-48*time.Hour))

	fresh := gcCLIRecord("svc-02", 3, now.Add(-12*time.Hour))

	prepareGCTestStore(
		t,
		storePath,
		history.Metadata{
			HistoryWindow: 1,
			HistoryTTL:    24 * time.Hour,
		},
		expired,
		protected,
		fresh,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gc",
			"--store",
			storePath,
			"--now",
			now.Format(time.RFC3339),
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(
		t,
		`{
  "deleted": 1,
  "kept": 2
}
`,
		stdout.String(),
	)

	assert.Empty(t, stderr.String())

	store, err := history.Open(storePath)
	require.NoError(t, err)

	svc01Records, err := store.List("svc-01")
	require.NoError(t, err)

	require.Len(t, svc01Records, 1)

	assert.Equal(t, protected.IssuedAt, svc01Records[0].IssuedAt)

	svc02Records, err := store.List("svc-02")
	require.NoError(t, err)

	require.Len(t, svc02Records, 1)

	assert.Equal(t, fresh.IssuedAt, svc02Records[0].IssuedAt)

	require.NoError(t, store.Close())
}

func TestRunGCEmptyStore(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	prepareGCTestStore(
		t,
		storePath,
		history.Metadata{
			HistoryWindow: 2,
			HistoryTTL:    24 * time.Hour,
		},
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		[]string{
			"--store",
			storePath,
			"--now",
			"2026-08-29T12:00:00Z",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(
		t,
		`{
  "deleted": 0,
  "kept": 0
}
`,
		stdout.String(),
	)

	assert.Empty(t, stderr.String())
}

func TestRunGCTTLZeroKeepsRecords(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)

	record := gcCLIRecord("svc-01", 1, now.Add(-1000*time.Hour))

	prepareGCTestStore(
		t,
		storePath,
		history.Metadata{
			HistoryWindow: 0,
			HistoryTTL:    0,
		},
		record,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		[]string{
			"--store",
			storePath,
			"--now",
			now.Format(time.RFC3339),
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), `"deleted": 0`)

	assert.Contains(t, stdout.String(), `"kept": 1`)

	assert.Empty(t, stderr.String())
}

func TestRunGCMissingMetadata(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		[]string{
			"--store",
			storePath,
			"--now",
			"2026-08-29T12:00:00Z",
		},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "history_metadata_not_found")
}

func TestRunGCHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		[]string{"--help"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "Usage:")

	assert.Contains(t, stdout.String(), "pwp gc --store <dir>")

	assert.Empty(t, stderr.String())
}

func TestRunGCMissingStore(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		nil,
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp gc: --store is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunGCInvalidNow(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		[]string{
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

	assert.Contains(t, stderr.String(), `pwp gc: invalid --now value "not-a-time"`)
}

func TestRunGCUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		[]string{"--unknown"},
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp gc:")

	assert.Contains(t, stderr.String(), "flag provided but not defined")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunGCUnexpectedArgument(t *testing.T) {
	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
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

	assert.Contains(t, stderr.String(), "pwp gc: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunGCCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runGC(
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

	assert.Contains(t, stderr.String(), "pwp gc: context canceled")
}

func TestRunGCStdoutWriteError(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "history")

	prepareGCTestStore(
		t,
		storePath,
		history.Metadata{
			HistoryWindow: 0,
			HistoryTTL:    0,
		},
	)

	writeErr := errors.New("forced write error")

	var stderr bytes.Buffer

	code := runGC(
		context.Background(),
		[]string{
			"--store",
			storePath,
			"--now",
			"2026-08-29T12:00:00Z",
		},
		gcErrorWriter{
			err: writeErr,
		},
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "pwp gc: write stdout: forced write error")
}

func TestWriteGCOutputShortWrite(t *testing.T) {
	err := writeGCOutput(gcShortWriter{}, []byte("gc result"))

	assert.ErrorIs(t, err, io.ErrShortWrite)
}

func prepareGCTestStore(t *testing.T, storePath string, metadata history.Metadata, records ...history.Record) {
	t.Helper()

	store, err := history.Open(storePath)
	require.NoError(t, err)

	require.NoError(t, store.SaveMetadata(metadata))

	for _, record := range records {
		require.NoError(t, store.Save(record))
	}

	require.NoError(t, store.Close())
}

func gcCLIRecord(subject string, number byte, issuedAt time.Time) history.Record {
	return history.Record{
		Subject: subject,

		Salt: []byte{
			number,
			number + 1,
			number + 2,
			number + 3,
		},

		Hash: []byte{
			number + 10,
			number + 11,
			number + 12,
			number + 13,
		},

		IssuedAt: issuedAt.UTC(),

		ExpiresAt: issuedAt.UTC().Add(7 * 24 * time.Hour),

		PolicyName:    "gc-test",
		PolicyVersion: "version-1",
	}
}

type gcErrorWriter struct {
	err error
}

func (w gcErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

type gcShortWriter struct{}

func (gcShortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	return len(data) - 1, nil
}
