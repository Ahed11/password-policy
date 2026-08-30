package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenStdoutDefaultCount(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "aaaaaaaaaaaa\n", stdout.String())

	assert.Empty(t, stderr.String())
}

func TestGenMultiplePasswords(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
			"--count",
			"3",
			"--out",
			"-",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "aaaaaaaaaaaa\n"+"aaaaaaaaaaaa\n"+"aaaaaaaaaaaa\n", stdout.String())

	assert.Empty(t, stderr.String())

	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")

	assert.Len(t, lines, 3)
}

func TestGenWritesFile(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	outputPath := filepath.Join(t.TempDir(), "passwords.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
			"--count",
			"2",
			"--out",
			outputPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Empty(t, stdout.String())

	assert.Empty(t, stderr.String())

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	assert.Equal(t, []byte("aaaaaaaaaaaa\n"+"aaaaaaaaaaaa\n"), data)
}

func TestGenOutputFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not reliably represented on Windows")
	}

	policyPath := writeGenTestPolicy(t)

	outputPath := filepath.Join(t.TempDir(), "password.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
			"--out",
			outputPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	require.Equal(t, exitSuccess, code)

	info, err := os.Stat(outputPath)
	require.NoError(t, err)

	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestGenMissingPolicyFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "--policy is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestGenMissingPolicyFile(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "missing.yaml")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp gen:")
}

func TestGenInvalidPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "invalid.yaml")

	err := os.WriteFile(
		policyPath,
		[]byte(
			`
version: 1
policy:
  name: test-policy
  classes:
    - name: letters
      alphabet: [
`,
		),
		0o600,
	)
	require.NoError(t, err)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.NotEmpty(t, stderr.String())
}

func TestGenCountZero(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
			"--count",
			"0",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "--count must be greater than zero")
}

func TestGenNegativeCount(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
			"--count",
			"-1",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "--count must be greater than zero")
}

func TestGenEmptyOutputPath(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
			"--out",
			"",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "--out must not be empty")
}

func TestGenUnexpectedArgument(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
			secretArgument,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp gen: unexpected positional argument")
	assert.NotContains(t, stderr.String(), secretArgument)
}

func TestGenUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--unknown",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "unknown")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestGenHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "short help",
			args: []string{
				"gen",
				"-h",
			},
		},
		{
			name: "long help",
			args: []string{
				"gen",
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

			assert.Contains(t, stdout.String(), "pwp gen --policy <file>")

			assert.Empty(t, stderr.String())
		},
		)
	}
}

func TestGenCanceledContext(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		ctx,
		[]string{
			"gen",
			"--policy",
			policyPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), context.Canceled.Error())
}

func TestGenStdoutWriteErrorDoesNotLeakPassword(t *testing.T) {
	policyPath := writeGenTestPolicy(t)

	writer := &genErrorWriter{
		err: errors.New("forced write failure"),
	}

	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"gen",
			"--policy",
			policyPath,
		},
		bytes.NewReader(nil),
		writer,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "forced write failure")

	assert.NotContains(t, stderr.String(), "aaaaaaaaaaaa")
}

func TestMarshalGeneratedPasswords(t *testing.T) {
	results := []app.GenerationResult{
		{
			Password: []byte("first"),
			Attempts: 1,
		},
		{
			Password: []byte("second"),
			Attempts: 2,
		},
	}

	data := marshalGeneratedPasswords(results)

	assert.Equal(t, []byte("first\nsecond\n"), data)
}

func TestMarshalGeneratedPasswordsEmpty(t *testing.T) {
	data := marshalGeneratedPasswords(nil)

	assert.Empty(t, data)
}

func TestZeroGenerationResults(t *testing.T) {
	first := []byte("first")
	second := []byte("second")

	results := []app.GenerationResult{
		{
			Password: first,
			Attempts: 1,
		},
		{
			Password: second,
			Attempts: 2,
		},
	}

	zeroGenerationResults(results)

	assert.Equal(t, []byte{0, 0, 0, 0, 0}, first)

	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0}, second)
}

func TestWriteGeneratedPasswords(t *testing.T) {
	var output bytes.Buffer

	err := writeGeneratedPasswords(&output, []byte("password\n"))

	require.NoError(t, err)

	assert.Equal(t, "password\n", output.String())
}

func TestWriteGeneratedPasswordsError(t *testing.T) {
	wantErr := errors.New("forced write failure")

	writer := &genErrorWriter{err: wantErr}

	err := writeGeneratedPasswords(writer, []byte("password\n"))

	assert.ErrorIs(t, err, wantErr)
}

func TestWriteGeneratedPasswordsShortWrite(t *testing.T) {
	writer := &genShortWriter{}

	err := writeGeneratedPasswords(writer, []byte("password\n"))

	assert.ErrorIs(t, err, io.ErrShortWrite)
}

func writeGenTestPolicy(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")

	err := os.WriteFile(
		path,
		[]byte(
			`
version: 1
policy:
  name: gen-test-policy
  length:
    min: 12
    max: 12
  classes:
    - name: letters
      alphabet: "a"
      min: 0
`,
		),
		0o600,
	)
	require.NoError(t, err)

	return path
}

type genErrorWriter struct {
	err error
}

func (w *genErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

type genShortWriter struct{}

func (w *genShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	return len(p) - 1, nil
}
