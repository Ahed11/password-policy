package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditGoldenReports(t *testing.T) {
	policyPath := writeAuditTestPolicyContent(
		t,
		"golden-policy.yaml",
		`
version: 1

policy:
  name: demo-service-accounts

  length:
    min: 16
    max: 20

  classes:
    - name: digits
      alphabet: "0123456789"
      min: 2

    - name: lower
      alphabet: "abcdefghijklmnopqrstuvwxyz"
      min: 2

    - name: upper
      alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      min: 2

    - name: special
      alphabet: '!@#$%^&*()-_=+[]{};:,.?'
      min: 1

  exclude: "lI1O0"

  attempts: 100

  forbid:
    repeat_run: 2
    repeat_total: false

    sequences:
      alphabet: 3
      keyboard: 3
      layouts:
        - qwerty
        - jcuken

    dictionary:
      path: ../../demo/dict/common.txt
      min_length: 4
      case_insensitive: true
      leet: true

    context:
      min_length: 3

issue:
  pool_size: 16
  store: build/history

  history:
    window: 5
    ttl: 180d

  rotate_after: 90d
`,
	)

	inputPath := filepath.Join("..", "..", "demo", "passwords.jsonl")

	outputDir := t.TempDir()

	reportPath := filepath.Join(outputDir, "audit.json")

	htmlPath := filepath.Join(outputDir, "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			reportPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)
	assert.Empty(t, stderr.String())

	assert.Contains(t, stdout.String(), "audit: checked=200 passed=120 failed=80 warnings=0")

	actualJSON, err := os.ReadFile(reportPath)
	require.NoError(t, err)

	expectedJSON, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "audit.json"))
	require.NoError(t, err)

	assert.Equal(t, string(expectedJSON), string(actualJSON))

	actualHTML, err := os.ReadFile(htmlPath)
	require.NoError(t, err)

	expectedHTML, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "audit.html"))
	require.NoError(t, err)

	assert.Equal(t, string(expectedHTML), string(actualHTML))
}

func TestAuditAllPasswordsPass(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"svc-01\",\"password\":\"aaaaaaaaaaaa\"}\n"+"{\"subject\":\"svc-02\",\"password\":\"aaaaaaaaaaaa\"}\n"))

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "checked=2")

	assert.Contains(t, stdout.String(), "passed=2")

	assert.Contains(t, stdout.String(), "failed=0")

	assert.Empty(t, stderr.String())

	jsonData, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	htmlData, err := os.ReadFile(htmlPath)
	require.NoError(t, err)

	assert.NotEmpty(t, jsonData)

	assert.NotEmpty(t, htmlData)

	var auditReport report.AuditReport

	err = json.Unmarshal(jsonData, &auditReport)
	require.NoError(t, err)

	assert.Equal(t, 2, auditReport.Totals.Checked)

	assert.Equal(t, 2, auditReport.Totals.Passed)

	assert.Equal(t, 0, auditReport.Totals.Failed)

	assert.Len(t, auditReport.Subjects, 2)
}

func TestAuditViolationReturnsFailure(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"svc-good\",\"password\":\"aaaaaaaaaaaa\"}\n"+"{\"subject\":\"svc-bad\",\"password\":\"aaaa\"}\n"))

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)

	assert.Contains(t, stdout.String(), "checked=2")

	assert.Contains(t, stdout.String(), "passed=1")

	assert.Contains(t, stdout.String(), "failed=1")

	assert.Empty(t, stderr.String())

	jsonData, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	var auditReport report.AuditReport

	err = json.Unmarshal(jsonData, &auditReport)
	require.NoError(t, err)

	assert.Equal(t, 2, auditReport.Totals.Checked)

	assert.Equal(t, 1, auditReport.Totals.Passed)

	assert.Equal(t, 1, auditReport.Totals.Failed)

	require.Len(t, auditReport.Violations, 1)

	assert.Equal(t, "length", auditReport.Violations[0].Rule)

	assert.Equal(t, 1, auditReport.Violations[0].Count)
}

func TestAuditEmptyInput(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "empty.jsonl", nil)

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "checked=0")

	assert.Contains(t, stdout.String(), "passed=0")

	assert.Contains(t, stdout.String(), "failed=0")

	assert.Empty(t, stderr.String())

	jsonData, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	var auditReport report.AuditReport

	err = json.Unmarshal(jsonData, &auditReport)
	require.NoError(t, err)

	assert.Equal(t, report.AuditTotals{}, auditReport.Totals)

	assert.Empty(t, auditReport.Subjects)

	assert.Empty(t, auditReport.Violations)
}

func TestAuditFromStdin(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	input := bytes.NewReader([]byte("{\"subject\":\"svc-01\",\"password\":\"aaaaaaaaaaaa\"}\n"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			"-",
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		input,
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "checked=1")

	assert.Empty(t, stderr.String())
}

func TestAuditMalformedLineNonStrict(t *testing.T) {
	policyPath := writeAuditControlPolicy(t)

	inputPath := filepath.Join("..", "..", "testdata", "control", "invalid_audit.jsonl")

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitSuccess, code)

	assert.Contains(t, stdout.String(), "checked=2")

	assert.Contains(t, stdout.String(), "warnings=1")

	assert.Contains(t, stderr.String(), "warning")

	assert.Contains(t, stderr.String(), "line 2")

	jsonData, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	var auditReport report.AuditReport

	err = json.Unmarshal(jsonData, &auditReport)
	require.NoError(t, err)

	assert.Equal(t, 2, auditReport.Totals.Checked)
}

func TestAuditMalformedLineStrict(t *testing.T) {
	policyPath := writeAuditControlPolicy(t)

	inputPath := filepath.Join("..", "..", "testdata", "control", "invalid_audit.jsonl")

	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "audit.json")

	htmlPath := filepath.Join(dir, "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
			"--strict",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "line 2")

	_, jsonErr := os.Stat(jsonPath)

	assert.True(t, os.IsNotExist(jsonErr))

	_, htmlErr := os.Stat(htmlPath)

	assert.True(t, os.IsNotExist(htmlErr))
}

func TestAuditReportsDoNotContainPasswords(t *testing.T) {
	const password = "P@ssword1234"

	policyPath := writeAuditTestPolicyContent(
		t,
		"secret-policy.yaml",
		`
version: 1
policy:
  name: secret-audit-policy
  length:
    min: 12
    max: 12
  classes:
    - name: all
      alphabet: "P@sword1234"
      min: 0
`,
	)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"svc-secret\",\"password\":\""+password+"\"}\n"))

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	require.Equal(t, exitSuccess, code)

	jsonData, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	htmlData, err := os.ReadFile(htmlPath)
	require.NoError(t, err)

	assert.NotContains(t, string(jsonData), password)

	assert.NotContains(t, string(htmlData), password)

	assert.NotContains(t, stdout.String(), password)

	assert.NotContains(t, stderr.String(), password)
}

func TestAuditReportsAreDeterministic(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"svc-02\",\"password\":\"aaaa\"}\n"+"{\"subject\":\"svc-01\",\"password\":\"aaaaaaaaaaaa\"}\n"))

	firstDir := t.TempDir()
	secondDir := t.TempDir()

	firstJSON := filepath.Join(firstDir, "audit.json")

	firstHTML := filepath.Join(firstDir, "audit.html")

	secondJSON := filepath.Join(secondDir, "audit.json")

	secondHTML := filepath.Join(secondDir, "audit.html")

	var firstStdout bytes.Buffer
	var firstStderr bytes.Buffer

	firstCode := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			firstJSON,
			"--report-html",
			firstHTML,
		},
		bytes.NewReader(nil),
		&firstStdout,
		&firstStderr,
	)

	require.Equal(t, exitFailure, firstCode)

	var secondStdout bytes.Buffer
	var secondStderr bytes.Buffer

	secondCode := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			secondJSON,
			"--report-html",
			secondHTML,
		},
		bytes.NewReader(nil),
		&secondStdout,
		&secondStderr,
	)

	require.Equal(t, exitFailure, secondCode)

	firstJSONData, err := os.ReadFile(firstJSON)
	require.NoError(t, err)

	secondJSONData, err := os.ReadFile(secondJSON)
	require.NoError(t, err)

	firstHTMLData, err := os.ReadFile(firstHTML)
	require.NoError(t, err)

	secondHTMLData, err := os.ReadFile(secondHTML)
	require.NoError(t, err)

	assert.Equal(t, firstJSONData, secondJSONData)

	assert.Equal(t, firstHTMLData, secondHTMLData)

	assert.Equal(t, firstStdout.String(), secondStdout.String())
}

func TestAuditHTMLEscapesSubject(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"<script>alert(1)</script>\",\"password\":\"aaaaaaaaaaaa\"}\n"))

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	require.Equal(t, exitSuccess, code)

	htmlData, err := os.ReadFile(htmlPath)
	require.NoError(t, err)

	assert.NotContains(t, string(htmlData), "<script>alert(1)</script>")

	assert.Contains(t, string(htmlData), "&lt;script&gt;")
}

func TestAuditReportPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not reliably represented on Windows")
	}

	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"svc-01\",\"password\":\"aaaaaaaaaaaa\"}\n"))

	jsonPath := filepath.Join(t.TempDir(), "audit.json")

	htmlPath := filepath.Join(t.TempDir(), "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			jsonPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	require.Equal(t, exitSuccess, code)

	jsonInfo, err := os.Stat(jsonPath)
	require.NoError(t, err)

	htmlInfo, err := os.Stat(htmlPath)
	require.NoError(t, err)

	assert.Equal(t, os.FileMode(0o600), jsonInfo.Mode().Perm())

	assert.Equal(t, os.FileMode(0o600), htmlInfo.Mode().Perm())
}

func TestAuditMissingPolicyFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--input",
			"-",
			"--report",
			"audit.json",
			"--report-html",
			"audit.html",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "--policy is required")
}

func TestAuditMissingInputFlag(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--report",
			"audit.json",
			"--report-html",
			"audit.html",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "--input is required")
}

func TestAuditMissingReportFlag(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			"-",
			"--report-html",
			"audit.html",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "--report is required")
}

func TestAuditMissingHTMLReportFlag(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			"-",
			"--report",
			"audit.json",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "--report-html is required")
}

func TestAuditMissingInputFile(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	dir := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			filepath.Join(
				dir,
				"missing.jsonl",
			),
			"--report",
			filepath.Join(
				dir,
				"audit.json",
			),
			"--report-html",
			filepath.Join(
				dir,
				"audit.html",
			),
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "open audit input")
}

func TestAuditSameReportPaths(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"svc-01\",\"password\":\"aaaaaaaaaaaa\"}\n"))

	reportPath := filepath.Join(t.TempDir(), "audit.out")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			reportPath,
			"--report-html",
			reportPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "must be different")
}

func TestAuditUnknownFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
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

func TestAuditUnexpectedArgument(t *testing.T) {
	const secretArgument = "Secret123!"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			secretArgument,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "pwp audit: unexpected positional argument")

	assert.NotContains(t, stderr.String(), secretArgument)
}

func TestAuditHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "short help",
			args: []string{
				"audit",
				"-h",
			},
		},
		{
			name: "long help",
			args: []string{
				"audit",
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

			assert.Contains(t, stdout.String(), "pwp audit --policy <file>")

			assert.Empty(t, stderr.String())
		},
		)
	}
}

func TestAuditCanceledContext(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		ctx,
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			"-",
			"--report",
			filepath.Join(
				dir,
				"audit.json",
			),
			"--report-html",
			filepath.Join(
				dir,
				"audit.html",
			),
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), context.Canceled.Error())
}

func TestAuditSummaryWriteError(t *testing.T) {
	policyPath := writeAuditTestPolicy(t)

	inputPath := writeAuditTestInput(t, "passwords.jsonl", []byte("{\"subject\":\"svc-01\",\"password\":\"aaaaaaaaaaaa\"}\n"))

	dir := t.TempDir()

	writer := &auditErrorWriter{
		err: errors.New("forced write failure"),
	}

	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			filepath.Join(
				dir,
				"audit.json",
			),
			"--report-html",
			filepath.Join(
				dir,
				"audit.html",
			),
		},
		bytes.NewReader(nil),
		writer,
		&stderr,
	)

	assert.Equal(t, exitUsage, code)

	assert.Contains(t, stderr.String(), "forced write failure")
}

func TestWriteAuditSummary(t *testing.T) {
	var output bytes.Buffer

	err := writeAuditSummary(&output, appAuditResultForTest())
	require.NoError(t, err)

	assert.Equal(t, "audit: checked=3 passed=2 failed=1 warnings=1\n", output.String())
}

func TestWriteAuditSummaryNilWriter(t *testing.T) {
	err := writeAuditSummary(nil, appAuditResultForTest())

	assert.Error(t, err)

	assert.ErrorContains(t, err, "writer must not be nil")
}

func TestAuditControlSet(t *testing.T) {
	policyPath := filepath.Join("..", "..", "testdata", "control", "valid_policy.yaml")

	inputPath := filepath.Join("..", "..", "testdata", "control", "passwords.jsonl")

	expectedPath := filepath.Join("..", "..", "testdata", "control", "expected_audit.json")

	outputDir := t.TempDir()

	outputPath := filepath.Join(outputDir, "audit.json")

	htmlPath := filepath.Join(outputDir, "audit.html")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{
			"audit",
			"--policy",
			policyPath,
			"--input",
			inputPath,
			"--report",
			outputPath,
			"--report-html",
			htmlPath,
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)

	assert.Equal(t, exitFailure, code)
	assert.Empty(t, stderr.String())

	assert.Contains(t, stdout.String(), "audit: checked=200 passed=120 failed=80 warnings=0")

	actual, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	expected, err := os.ReadFile(expectedPath)
	require.NoError(t, err)

	assert.Equal(t, string(expected), string(actual))
}

func writeAuditTestPolicy(t *testing.T) string {
	t.Helper()

	return writeAuditTestPolicyContent(
		t,
		"policy.yaml",
		`
version: 1
policy:
  name: audit-test-policy
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

func writeAuditTestPolicyContent(t *testing.T, name string, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)

	return path
}

func writeAuditTestInput(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	err := os.WriteFile(path, data, 0o600)
	require.NoError(t, err)

	return path
}

type auditErrorWriter struct {
	err error
}

func (w *auditErrorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func appAuditResultForTest() app.AuditResult {
	return app.AuditResult{
		Policy:  "audit-test-policy",
		Checked: 3,
		Passed:  2,
		Failed:  1,

		LineErrors: []app.AuditLineError{
			{
				Line:    2,
				Message: "broken line",
			},
		},
	}
}

func writeAuditControlPolicy(t *testing.T) string {
	t.Helper()

	return writeAuditTestPolicyContent(
		t,
		"control-policy.yaml",
		`
version: 1
policy:
  name: audit-control-policy
  length:
    min: 18
    max: 18
  classes:
    - name: all
      alphabet: "A7!m2#Q9$v4&Z6*e8?"
      min: 1
`,
	)
}
