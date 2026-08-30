package main

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunMainVersion(t *testing.T) {
	code, stdout, stderr := runMainForTest(t, []string{"version"})

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "pwp dev\n", stdout)

	assert.Empty(t, stderr)
}

func TestRunMainWithoutArguments(t *testing.T) {
	code, stdout, stderr := runMainForTest(t, nil)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout)

	assert.Contains(t, stderr, "Usage:")
	assert.Contains(t, stderr, "pwp [global options] <command> [options]")
}

func runMainForTest(t *testing.T, args []string) (int, string, string) {
	t.Helper()

	oldArgs := os.Args
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	require.NoError(t, err)

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr-*")
	require.NoError(t, err)

	os.Args = append([]string{"pwp"}, args...)

	os.Stdout = stdoutFile
	os.Stderr = stderrFile

	code := runMain()

	os.Args = oldArgs
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	stdout := readMainTestFile(t, stdoutFile)

	stderr := readMainTestFile(t, stderrFile)

	require.NoError(t, stdoutFile.Close())
	require.NoError(t, stderrFile.Close())

	return code, stdout, stderr
}

func readMainTestFile(t *testing.T, file *os.File) string {
	t.Helper()

	_, err := file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	data, err := io.ReadAll(file)
	require.NoError(t, err)

	return string(data)
}
