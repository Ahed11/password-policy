package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAuditCreatesReports(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "audit.json")

	htmlPath := filepath.Join(dir, "audit.html")

	report := writeTestAuditReport()

	expectedJSON, err := MarshalJSON(report)
	require.NoError(t, err)

	expectedHTML, err := MarshalHTML(report)
	require.NoError(t, err)

	err = WriteAudit(report, jsonPath, htmlPath)
	require.NoError(t, err)

	gotJSON, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	gotHTML, err := os.ReadFile(htmlPath)
	require.NoError(t, err)

	assert.Equal(t, expectedJSON, gotJSON)

	assert.Equal(t, expectedHTML, gotHTML)
}

func TestWriteAuditReplacesExistingReports(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "audit.json")

	htmlPath := filepath.Join(dir, "audit.html")

	err := os.WriteFile(jsonPath, []byte("old json"), 0600)
	require.NoError(t, err)

	err = os.WriteFile(htmlPath, []byte("old html"), 0600)
	require.NoError(t, err)

	report := writeTestAuditReport()

	expectedJSON, err := MarshalJSON(report)
	require.NoError(t, err)

	expectedHTML, err := MarshalHTML(report)
	require.NoError(t, err)

	err = WriteAudit(report, jsonPath, htmlPath)
	require.NoError(t, err)

	gotJSON, err := os.ReadFile(jsonPath)
	require.NoError(t, err)

	gotHTML, err := os.ReadFile(htmlPath)
	require.NoError(t, err)

	assert.Equal(t, expectedJSON, gotJSON)

	assert.Equal(t, expectedHTML, gotHTML)

	assert.NotEqual(t, []byte("old json"), gotJSON)

	assert.NotEqual(t, []byte("old html"), gotHTML)
}

func TestWriteAuditEmptyJSONPath(t *testing.T) {
	err := WriteAudit(writeTestAuditReport(), "", "audit.html")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "JSON path must not be empty")
}

func TestWriteAuditEmptyHTMLPath(t *testing.T) {
	err := WriteAudit(writeTestAuditReport(), "audit.json", "")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "HTML path must not be empty")
}

func TestWriteAuditSamePath(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "audit.report")

	err := WriteAudit(writeTestAuditReport(), path, path)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "JSON and HTML paths must be different")

	_, statErr := os.Stat(path)

	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestWriteAuditJSONWriteError(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "missing", "audit.json")

	htmlPath := filepath.Join(dir, "audit.html")

	report := writeTestAuditReport()

	expectedHTML, err := MarshalHTML(report)
	require.NoError(t, err)

	err = WriteAudit(report, jsonPath, htmlPath)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "write audit JSON report")

	_, statErr := os.Stat(jsonPath)

	assert.ErrorIs(t, statErr, os.ErrNotExist)

	gotHTML, readErr := os.ReadFile(htmlPath)
	require.NoError(t, readErr)

	assert.Equal(t, expectedHTML, gotHTML)
}

func TestWriteAuditHTMLWriteError(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "audit.json")

	htmlPath := filepath.Join(dir, "missing", "audit.html")

	report := writeTestAuditReport()

	expectedJSON, err := MarshalJSON(report)
	require.NoError(t, err)

	err = WriteAudit(report, jsonPath, htmlPath)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "write audit HTML report")

	gotJSON, readErr := os.ReadFile(jsonPath)
	require.NoError(t, readErr)

	assert.Equal(t, expectedJSON, gotJSON)

	_, statErr := os.Stat(htmlPath)

	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestWriteAuditJoinsWriteErrors(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "missing-json", "audit.json")

	htmlPath := filepath.Join(dir, "missing-html", "audit.html")

	err := WriteAudit(writeTestAuditReport(), jsonPath, htmlPath)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "write audit JSON report")

	assert.ErrorContains(t, err, "write audit HTML report")
}

func writeTestAuditReport() AuditReport {
	return AuditReport{
		ReportVersion: 1,
		Policy:        "service-accounts",
		Totals: AuditTotals{
			Checked: 2,
			Passed:  1,
			Failed:  1,
		},
		Violations: []ViolationCount{
			{
				Rule:  "dictionary",
				Count: 1,
			},
		},
		Subjects: []AuditSubject{
			{
				Subject: "svc-01",
				Passed:  false,
				Rules: []string{
					"dictionary",
				},
			},
			{
				Subject: "svc-02",
				Passed:  true,
				Rules:   []string{},
			},
		},
	}
}
