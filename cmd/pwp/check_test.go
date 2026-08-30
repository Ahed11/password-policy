package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPassingPasswordFromFile(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "password satisfies policy")

	assert.Contains(t, stdout.String(), "check-test-policy")

	assert.Empty(t, stderr.String())
}

func TestCheckPassingPasswordFromStdin(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			"-",
		},
		bytes.NewReader(
			[]byte("aaaaaaaaaaaa\n"),
		),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "password satisfies policy")

	assert.Empty(t, stderr.String())
}

func TestCheckViolationReturnsFailure(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.Contains(t, stdout.String(), "password does not satisfy policy")

	assert.Contains(t, stdout.String(), "length FAILED")

	assert.Empty(t, stderr.String())
}

func TestCheckContextViolation(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
			"--context",
			"login=aaa",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.Contains(t, stdout.String(), "password does not satisfy policy")

	assert.Contains(t, stdout.String(), "context")

	assert.NotContains(t, stderr.String(), "aaa")
}

func TestCheckRepeatedContextFlags(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
			"--context",
			"login=bbb",
			"--context",
			"host=aaa",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.Contains(t, stdout.String(), "context")

	assert.Empty(t, stderr.String())
}

func TestCheckInvalidContextFormat(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
			"--context",
			"invalid",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "context must be in key=value form")
}

func TestCheckEmptyContextValue(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
			"--context",
			"login=",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "context value")
}

func TestCheckMissingPolicyFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--password-file",
			"-",
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

func TestCheckMissingPasswordFileFlag(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "--password-file is required")

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestCheckMissingPolicyFile(t *testing.T) {
	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	policyPath := filepath.Join(t.TempDir(), "missing.yaml")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp check:")
}

func TestCheckMissingPasswordFile(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := filepath.Join(t.TempDir(), "missing.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "read password file")
}

func TestCheckUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
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

func TestCheckUnexpectedArgument(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
			secretArgument,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp check: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)
}

func TestCheckHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "short help",
			args: []string{
				"check",
				"-h",
			},
		},
		{
			name: "long help",
			args: []string{
				"check",
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

			assert.Contains(t, stdout.String(), "pwp check --policy <file>")

			assert.Empty(t, stderr.String())
		},
		)
	}
}

func TestCheckCanceledContext(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		ctx,
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), context.Canceled.Error())
}

func TestCheckResultWriteErrorDoesNotLeakPassword(t *testing.T) {
	policyPath := writeCheckTestPolicy(t)

	const password = "aaaaaaaaaaaa"

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte(password))

	writer := &checkErrorWriter{
		err: errors.New("forced write failure"),
	}

	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		writer,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "forced write failure")

	assert.NotContains(t, stderr.String(), password)
}

func TestReadCheckPasswordLF(t *testing.T) {
	path := writeCheckTestPassword(t, "password.txt", []byte("password\n"))

	password, err := readCheckPassword(path, bytes.NewReader(nil))
	require.NoError(t, err)

	assert.Equal(t, []byte("password"), password)
}

func TestReadCheckPasswordCRLF(t *testing.T) {
	path := writeCheckTestPassword(t, "password.txt", []byte("password\r\n"))

	password, err := readCheckPassword(path, bytes.NewReader(nil))
	require.NoError(t, err)

	assert.Equal(t, []byte("password"), password)
}

func TestReadCheckPasswordPreservesSpaces(t *testing.T) {
	path := writeCheckTestPassword(t, "password.txt", []byte(" password \n"))

	password, err := readCheckPassword(path, bytes.NewReader(nil))
	require.NoError(t, err)

	assert.Equal(t, []byte(" password "), password)
}

func TestReadCheckPasswordRemovesOnlyOneLineEnding(t *testing.T) {
	path := writeCheckTestPassword(t, "password.txt", []byte("password\n\n"))

	password, err := readCheckPassword(path, bytes.NewReader(nil))
	require.NoError(t, err)

	assert.Equal(t, []byte("password\n"), password)
}

func TestReadCheckPasswordFromStdin(t *testing.T) {
	password, err := readCheckPassword("-", bytes.NewReader([]byte("password\n")))
	require.NoError(t, err)

	assert.Equal(t, []byte("password"), password)
}

func TestReadCheckPasswordStdinError(t *testing.T) {
	reader := &checkErrorReader{
		err: errors.New("forced read failure"),
	}

	password, err := readCheckPassword("-", reader)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "read password from stdin")

	assert.Nil(t, password)
}

func TestContextValuesFlag(t *testing.T) {
	var values contextValuesFlag

	require.NoError(t, values.Set("login=svc-01"))

	require.NoError(t, values.Set("host=server-01"))

	assert.Equal(
		t,
		[]string{
			"svc-01",
			"server-01",
		},
		values.values,
	)
}

func TestContextValuesFlagEmptyKey(t *testing.T) {
	var values contextValuesFlag

	err := values.Set("=svc-01")

	assert.Error(t, err)

	assert.Empty(t, values.values)
}

func TestContextValuesFlagEmptyValue(t *testing.T) {
	var values contextValuesFlag

	err := values.Set("login=")

	assert.Error(t, err)

	assert.Empty(t, values.values)
}

func TestCheckCustomKeyboardLayoutFromPolicyFile(t *testing.T) {
	tempDir := t.TempDir()

	layoutPath := filepath.Join(tempDir, "custom-layout.txt")

	err := os.WriteFile(layoutPath, []byte("12345\nabcde\n"), 0o600)
	require.NoError(t, err)

	policyPath := filepath.Join(tempDir, "policy.yaml")

	policyContent := fmt.Sprintf(
		`version: 1
policy:
  name: custom-layout-policy
  length:
    min: 3
    max: 3
  classes:
    - name: symbols
      alphabet: "12345"
      min: 0
  forbid:
    sequences:
      keyboard: 3
      layouts:
        - %q
`,
		filepath.ToSlash(layoutPath),
	)

	err = os.WriteFile(policyPath, []byte(policyContent), 0o600)
	require.NoError(t, err)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("123\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.Contains(t, stdout.String(), "sequences.keyboard FAILED at offset 0, length 3")

	assert.Contains(t, stdout.String(), "custom-layout.txt")

	assert.Empty(t, stderr.String())
}

func TestCheckMissingCustomKeyboardLayoutFile(t *testing.T) {
	tempDir := t.TempDir()

	layoutPath := filepath.Join(tempDir, "missing-layout.txt")

	policyPath := filepath.Join(tempDir, "policy.yaml")

	policyContent := fmt.Sprintf(
		`version: 1
policy:
  name: missing-layout-policy
  length:
    min: 3
    max: 3
  classes:
    - name: symbols
      alphabet: "12345"
      min: 0
  forbid:
    sequences:
      keyboard: 3
      layouts:
        - %q
`,
		filepath.ToSlash(layoutPath),
	)

	err := os.WriteFile(policyPath, []byte(policyContent), 0o600)
	require.NoError(t, err)

	passwordPath := writeCheckTestPassword(t, "password.txt", []byte("123\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"check",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "prepare keyboard layouts")

	assert.Contains(t, stderr.String(), "missing-layout.txt")
}

func TestCheckControlIndividualRuleViolations(t *testing.T) {
	controlDir := filepath.Join(
		"..",
		"..",
		"testdata",
		"control",
	)

	tests := []struct {
		name         string
		policy       string
		password     string
		extraArgs    []string
		expectedLine string
	}{
		{
			name:         "class_lower",
			policy:       "valid_policy.yaml",
			password:     "missing_lower.txt",
			expectedLine: "class lower FAILED",
		},
		{
			name:         "repeat_total",
			policy:       "repeat_total_policy.yaml",
			password:     "repeat_total.txt",
			expectedLine: "repeat_total FAILED",
		},
		{
			name:     "context",
			policy:   "valid_policy.yaml",
			password: "context.txt",
			extraArgs: []string{
				"--context",
				"login=svc-01",
			},
			expectedLine: "context FAILED",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policyPath := filepath.Join(controlDir, test.policy)

			passwordPath := filepath.Join(controlDir, "passwords", test.password)

			args := []string{"check", "--policy", policyPath, "--password-file", passwordPath}

			args = append(args, test.extraArgs...)

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(context.Background(), args, bytes.NewReader(nil), &stdout, &stderr)

			assert.Equal(t, exitFailure, code)
			assert.Empty(t, stderr.String())

			assert.Contains(t, stdout.String(), test.expectedLine)

			assert.Equal(t, 1, strings.Count(stdout.String(), "FAILED"), "control password must violate exactly one rule")
		})
	}
}

func TestCheckControlBoundaryPasswords(t *testing.T) {
	controlDir := filepath.Join("..", "..", "testdata", "control")

	policyPath := filepath.Join(controlDir, "valid_policy.yaml")

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "length_min",
			password: "boundary_length_min.txt",
		},
		{
			name:     "length_max",
			password: "boundary_length_max.txt",
		},
		{
			name:     "repeat_run_at_limit",
			password: "boundary_repeat_run.txt",
		},
		{
			name:     "alphabet_sequence_below_limit",
			password: "boundary_alphabet_sequence.txt",
		},
		{
			name:     "keyboard_sequence_below_limit",
			password: "boundary_keyboard_sequence.txt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			passwordPath := filepath.Join(controlDir, "passwords", test.password)

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{
					"check",
					"--policy",
					policyPath,
					"--password-file",
					passwordPath,
				},
				bytes.NewReader(nil),
				&stdout,
				&stderr,
			)

			assert.Equal(t, exitSuccess, code)
			assert.Empty(t, stderr.String())

			assert.Contains(t, stdout.String(), "password satisfies policy")
		})
	}
}

func TestCheckControlClassMinimumBoundaries(t *testing.T) {
	controlDir := filepath.Join("..", "..", "testdata", "control")

	policyPath := filepath.Join(controlDir, "valid_policy.yaml")

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "digits_at_minimum",
			password: "boundary_class_digits.txt",
		},
		{
			name:     "lower_at_minimum",
			password: "boundary_class_lower.txt",
		},
		{
			name:     "upper_at_minimum",
			password: "boundary_class_upper.txt",
		},
		{
			name:     "special_at_minimum",
			password: "boundary_class_special.txt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			passwordPath := filepath.Join(controlDir, "passwords", test.password)

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{
					"check",
					"--policy",
					policyPath,
					"--password-file",
					passwordPath,
				},
				bytes.NewReader(nil),
				&stdout,
				&stderr,
			)

			assert.Equal(t, exitSuccess, code)
			assert.Empty(t, stderr.String())

			assert.Contains(t, stdout.String(), "password satisfies policy")
		})
	}
}

func TestCheckControlSpecialBoundaries(t *testing.T) {
	controlDir := filepath.Join("..", "..", "testdata", "control")

	tests := []struct {
		name         string
		policy       string
		password     string
		extraArgs    []string
		expectedCode int
		expectedLine string
	}{
		{
			name:         "repeat_total_one_occurrence",
			policy:       "repeat_total_policy.yaml",
			password:     "boundary_repeat_total.txt",
			expectedCode: exitSuccess,
			expectedLine: "password satisfies policy",
		},
		{
			name:         "dictionary_below_min_length",
			policy:       "dictionary_boundary_policy.yaml",
			password:     "boundary_dictionary_below.txt",
			expectedCode: exitSuccess,
			expectedLine: "password satisfies policy",
		},
		{
			name:         "dictionary_at_min_length",
			policy:       "dictionary_boundary_policy.yaml",
			password:     "boundary_dictionary_at.txt",
			expectedCode: exitFailure,
			expectedLine: "dictionary FAILED",
		},
		{
			name:     "context_below_min_length",
			policy:   "valid_policy.yaml",
			password: "boundary_context_below.txt",
			extraArgs: []string{
				"--context",
				"login=svc",
			},
			expectedCode: exitSuccess,
			expectedLine: "password satisfies policy",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policyPath := filepath.Join(controlDir, test.policy)

			passwordPath := filepath.Join(controlDir, "passwords", test.password)

			args := []string{"check", "--policy", policyPath, "--password-file", passwordPath}

			args = append(args, test.extraArgs...)

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(context.Background(), args, bytes.NewReader(nil), &stdout, &stderr)

			assert.Equal(t, test.expectedCode, code)
			assert.Empty(t, stderr.String())

			assert.Contains(t, stdout.String(), test.expectedLine)
		})
	}
}

func writeCheckTestPolicy(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")

	err := os.WriteFile(
		path,
		[]byte(
			`
version: 1
policy:
  name: check-test-policy
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

func writeCheckTestPassword(t *testing.T, name string, password []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	err := os.WriteFile(path, password, 0o600)
	require.NoError(t, err)

	return path
}

type checkErrorWriter struct {
	err error
}

func (w *checkErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

type checkErrorReader struct {
	err error
}

func (r *checkErrorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

var _ io.Reader = (*checkErrorReader)(nil)
var _ io.Writer = (*checkErrorWriter)(nil)
