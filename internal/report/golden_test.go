package report

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool(
	"update",
	false,
	"update golden report files",
)

func TestGoldenAuditReports(t *testing.T) {
	report := goldenAuditReport()

	tests := []struct {
		name     string
		fileName string
		marshal  func(AuditReport) ([]byte, error)
	}{
		{
			name:     "json",
			fileName: "audit.json",
			marshal:  MarshalJSON,
		},
		{
			name:     "html",
			fileName: "audit.html",
			marshal:  MarshalHTML,
		},
	}

	for _, testCase := range tests {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			actual, err := testCase.marshal(report)
			require.NoError(t, err)

			goldenPath := filepath.Join("..", "..", "testdata", "golden", testCase.fileName)

			if *updateGolden {
				err := os.WriteFile(goldenPath, actual, 0o600)
				require.NoError(t, err)
			}

			expected, err := os.ReadFile(goldenPath)
			require.NoError(t, err)

			assert.Equal(t, string(normalizeGoldenNewlines(expected)), string(normalizeGoldenNewlines(actual)))
		},
		)
	}
}

func goldenAuditReport() AuditReport {
	subjects := make([]AuditSubject, 0, 200)

	for i := 1; i <= 120; i++ {
		subjects = append(
			subjects,
			AuditSubject{
				Subject: fmt.Sprintf("pass-%03d", i),
				Passed:  true,
				Rules:   []string{},
			},
		)
	}

	groups := []struct {
		prefix string
		rule   string
	}{
		{
			prefix: "fail-length",
			rule:   "length",
		},
		{
			prefix: "fail-upper",
			rule:   "class.upper",
		},
		{
			prefix: "fail-special",
			rule:   "class.special",
		},
		{
			prefix: "fail-repeat",
			rule:   "repeat_run",
		},
		{
			prefix: "fail-alphabet",
			rule:   "sequences.alphabet",
		},
		{
			prefix: "fail-keyboard",
			rule:   "sequences.keyboard",
		},
		{
			prefix: "fail-dictionary",
			rule:   "dictionary",
		},
		{
			prefix: "fail-digits",
			rule:   "class.digits",
		},
	}

	for _, group := range groups {
		for i := 1; i <= 10; i++ {
			subjects = append(
				subjects,
				AuditSubject{
					Subject: fmt.Sprintf("%s-%03d", group.prefix, i),
					Passed:  false,
					Rules: []string{
						group.rule,
					},
				},
			)
		}
	}

	return AuditReport{
		ReportVersion: 1,
		Policy:        "demo-service-accounts",
		Totals: AuditTotals{
			Checked: 200,
			Passed:  120,
			Failed:  80,
		},
		Violations: []ViolationCount{
			{
				Rule:  "class.digits",
				Count: 10,
			},
			{
				Rule:  "class.special",
				Count: 10,
			},
			{
				Rule:  "class.upper",
				Count: 10,
			},
			{
				Rule:  "dictionary",
				Count: 10,
			},
			{
				Rule:  "length",
				Count: 10,
			},
			{
				Rule:  "repeat_run",
				Count: 10,
			},
			{
				Rule:  "sequences.alphabet",
				Count: 10,
			},
			{
				Rule:  "sequences.keyboard",
				Count: 10,
			},
		},
		Subjects: subjects,
	}
}

func normalizeGoldenNewlines(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}
