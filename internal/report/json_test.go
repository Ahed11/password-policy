package report

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalJSON(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "service-accounts",
		Totals: AuditTotals{
			Checked: 3,
			Passed:  1,
			Failed:  2,
		},
		Violations: []ViolationCount{
			{
				Rule:  "class.digits",
				Count: 1,
			},
			{
				Rule:  "dictionary",
				Count: 2,
			},
		},
		Subjects: []AuditSubject{
			{
				Subject: "svc-01",
				Passed:  false,
				Rules: []string{
					"class.digits",
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

	got, err := MarshalJSON(report)

	require.NoError(t, err)

	want := []byte(`{
  "report_version": 1,
  "policy": "service-accounts",
  "totals": {
    "checked": 3,
    "passed": 1,
    "failed": 2
  },
  "violations": [
    {
      "rule": "class.digits",
      "count": 1
    },
    {
      "rule": "dictionary",
      "count": 2
    }
  ],
  "subjects": [
    {
      "subject": "svc-01",
      "passed": false,
      "rules": [
        "class.digits",
        "dictionary"
      ]
    },
    {
      "subject": "svc-02",
      "passed": true,
      "rules": []
    }
  ]
}
`)

	assert.Equal(t, want, got)
}

func TestMarshalJSONEmptyReport(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "empty-policy",
		Violations:    []ViolationCount{},
		Subjects:      []AuditSubject{},
	}

	got, err := MarshalJSON(report)

	require.NoError(t, err)

	want := []byte(`{
  "report_version": 1,
  "policy": "empty-policy",
  "totals": {
    "checked": 0,
    "passed": 0,
    "failed": 0
  },
  "violations": [],
  "subjects": []
}
`)

	assert.Equal(t, want, got)
}

func TestMarshalJSONDeterministic(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "test-policy",
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
			{
				Rule:  "repeat_run",
				Count: 1,
			},
		},
		Subjects: []AuditSubject{
			{
				Subject: "svc-01",
				Passed:  false,
				Rules: []string{
					"dictionary",
					"repeat_run",
				},
			},
			{
				Subject: "svc-02",
				Passed:  true,
				Rules:   []string{},
			},
		},
	}

	first, err := MarshalJSON(report)
	require.NoError(t, err)

	second, err := MarshalJSON(report)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(first, second), "same report must produce identical JSON bytes")
}

func TestMarshalJSONEndsWithSingleNewline(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "test-policy",
		Violations:    []ViolationCount{},
		Subjects:      []AuditSubject{},
	}

	data, err := MarshalJSON(report)

	require.NoError(t, err)
	require.NotEmpty(t, data)

	assert.Equal(t, byte('\n'), data[len(data)-1])

	assert.False(t, bytes.HasSuffix(data, []byte{'\n', '\n'}))
}

func TestMarshalJSONDoesNotContainPasswordField(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "test-policy",
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
		},
	}

	data, err := MarshalJSON(report)

	require.NoError(t, err)

	assert.NotContains(t, string(data), `"password"`)

	assert.NotContains(t, string(data), `"password_hash"`)
}
