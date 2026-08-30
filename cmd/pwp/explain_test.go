package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExplainPassingPasswordFromFile(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stdout.String(), `policy: "explain-test-policy"`)

	assert.Contains(t, stdout.String(), "passed: PASS")

	assert.Contains(t, stdout.String(), "length: PASS")

	assert.Contains(t, stdout.String(), "class letters: PASS")

	assert.Contains(t, stdout.String(), "rule repeat_run: PASS")

	assert.Contains(t, stdout.String(), "rule context: PASS")

	assert.Empty(t, stderr.String())
}

func TestExplainPassingPasswordFromStdin(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stdout.String(), "passed: PASS")

	assert.Empty(t, stderr.String())
}

func TestExplainLengthViolationReturnsFailure(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte("aaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stdout.String(), "passed: FAIL")

	assert.Contains(t, stdout.String(), "length: FAIL")

	assert.Empty(t, stderr.String())
}

func TestExplainClassViolation(t *testing.T) {
	policyPath := writeExplainTestPolicyContent(
		t,
		"class-policy.yaml",
		`
version: 1
policy:
  name: class-policy
  length:
    min: 12
    max: 12
  classes:
    - name: letters
      alphabet: "a"
      min: 1
    - name: digits
      alphabet: "1"
      min: 1
`,
	)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stdout.String(), "class letters: PASS")

	assert.Contains(t, stdout.String(), "class digits: FAIL")

	assert.Empty(t, stderr.String())
}

func TestExplainRepeatRunViolation(t *testing.T) {
	const password = "aaaaaaaaaaaa"

	policyPath := writeExplainTestPolicyContent(
		t,
		"repeat.yaml",
		`
version: 1
policy:
  name: repeat-policy
  length:
    min: 12
    max: 12
  classes:
    - name: letters
      alphabet: "a"
      min: 0
  forbid:
    repeat_run: 3
`,
	)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte(password))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stdout.String(), "rule repeat_run: FAIL")

	assert.Contains(t, stdout.String(), "violation: offset")

	assert.NotContains(t, stdout.String(), password)

	assert.NotContains(t, stderr.String(), password)

	assert.Empty(t, stderr.String())
}

func TestExplainContextViolation(t *testing.T) {
	const password = "aaaaaaaaaaaa"

	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte(password))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stdout.String(), "rule context: FAIL")

	assert.Contains(t, stdout.String(), "violation: offset")

	assert.NotContains(t, stdout.String(), password)

	assert.NotContains(t, stderr.String(), password)

	assert.Empty(t, stderr.String())
}

func TestExplainRepeatedContextFlags(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stdout.String(), "rule context: FAIL")

	assert.Empty(t, stderr.String())
}

func TestExplainRuleOrderIsDeterministic(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
			"--policy",
			policyPath,
			"--password-file",
			passwordPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	require.Equal(t, exitSuccess, code)

	output := stdout.String()

	ruleNames := []string{
		"repeat_run",
		"repeat_total",
		"sequences.alphabet",
		"sequences.keyboard",
		"dictionary",
		"context",
	}

	lastIndex := -1

	for _, ruleName := range ruleNames {
		index := strings.Index(output, "rule "+ruleName+":")

		require.Greater(t, index, lastIndex, "rule %q must appear after the previous rule", ruleName)

		lastIndex = index
	}
}

func TestExplainMissingPolicyFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

func TestExplainMissingPasswordFileFlag(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

func TestExplainInvalidContextFormat(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
			"--policy",
			policyPath,
			"--password-file",
			"-",
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

func TestExplainMissingPolicyFile(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "missing.yaml")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
			"--policy",
			policyPath,
			"--password-file",
			"-",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp explain:")
}

func TestExplainMissingPasswordFile(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	passwordPath := filepath.Join(t.TempDir(), "missing.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

func TestExplainUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

func TestExplainUnexpectedArgument(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa"))

	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

	assert.Contains(t, stderr.String(), "pwp explain: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)
}

func TestExplainHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "short help",
			args: []string{
				"explain",
				"-h",
			},
		},
		{
			name: "long help",
			args: []string{
				"explain",
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

			assert.Contains(t, stdout.String(), "pwp explain --policy <file>")

			assert.Empty(t, stderr.String())
		},
		)
	}
}

func TestExplainCanceledContext(t *testing.T) {
	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte("aaaaaaaaaaaa"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		ctx,
		[]string{
			"explain",
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

func TestExplainWriteErrorDoesNotLeakPassword(t *testing.T) {
	const password = "aaaaaaaaaaaa"

	policyPath := writeExplainTestPolicy(t)

	passwordPath := writeExplainTestPassword(t, "password.txt", []byte(password))

	writer := &explainErrorWriter{
		err: errors.New("forced write failure"),
	}

	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"explain",
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

func TestWriteExplainResult(t *testing.T) {
	explanation := app.Explanation{
		Passed: false,

		Length: rules.LengthResult{
			Count:  4,
			Min:    12,
			Max:    12,
			Passed: false,
		},

		Classes: []rules.ClassResult{
			{
				Name:    "letters",
				Count:   4,
				Minimum: 1,
				Passed:  true,
			},
		},

		Rules: []app.RuleExplanation{
			{
				Rule:   "repeat_run",
				Passed: false,
				Violations: []rules.Violation{
					{
						Rule:   "repeat_run",
						Offset: 1,
						Length: 3,
					},
				},
			},
			{
				Rule:   "sequences.keyboard",
				Passed: false,
				Violations: []rules.Violation{
					{
						Rule:   "sequences.keyboard",
						Offset: 2,
						Length: 4,
						Layout: "qwerty",
					},
				},
			},
		},
	}

	var output bytes.Buffer

	err := writeExplainResult(&output, "test-policy", explanation)
	require.NoError(t, err)

	assert.Contains(t, output.String(), `policy: "test-policy"`)

	assert.Contains(t, output.String(), "passed: FAIL")

	assert.Contains(t, output.String(), "length: FAIL (count 4, allowed 12..12)")

	assert.Contains(t, output.String(), "class letters: PASS (count 4, min 1)")

	assert.Contains(t, output.String(), "rule repeat_run: FAIL")

	assert.Contains(t, output.String(), "violation: offset 1, length 3")

	assert.Contains(t, output.String(), "layout qwerty")
}

func TestWriteExplainResultNilWriter(t *testing.T) {
	err := writeExplainResult(nil, "test-policy", app.Explanation{})

	assert.Error(t, err)

	assert.ErrorContains(t, err, "writer must not be nil")
}

func TestPassFail(t *testing.T) {
	assert.Equal(t, "PASS", passFail(true))

	assert.Equal(t, "FAIL", passFail(false))
}

func writeExplainTestPolicy(t *testing.T) string {
	t.Helper()

	return writeExplainTestPolicyContent(
		t,
		"policy.yaml",
		`
version: 1
policy:
  name: explain-test-policy
  length:
    min: 12
    max: 12
  classes:
    - name: letters
      alphabet: "a"
      min: 0
`,
	)
}

func writeExplainTestPolicyContent(t *testing.T, name string, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)

	return path
}

func writeExplainTestPassword(t *testing.T, name string, password []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	err := os.WriteFile(path, password, 0o600)
	require.NoError(t, err)

	return path
}

type explainErrorWriter struct {
	err error
}

func (w *explainErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}
