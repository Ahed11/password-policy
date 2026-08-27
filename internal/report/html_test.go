package report

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalHTML(t *testing.T) {
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

	data, err := MarshalHTML(report)

	require.NoError(t, err)

	html := string(data)

	assert.Contains(t, html, "<title>Password Policy Audit Report</title>")

	assert.Contains(t, html, "<strong>Report version:</strong> 1")

	assert.Contains(t, html, "<strong>Policy:</strong> service-accounts")

	assert.Contains(t, html, "<td>3</td>")
	assert.Contains(t, html, "<td>1</td>")
	assert.Contains(t, html, "<td>2</td>")

	assert.Contains(t, html, "<td>class.digits</td>")
	assert.Contains(t, html, "<td>dictionary</td>")

	assert.Contains(t, html, "<td>svc-01</td>")
	assert.Contains(t, html, "<td>svc-02</td>")

	assert.Contains(t, html, `<span class="failed">failed</span>`)

	assert.Contains(t, html, `<span class="passed">passed</span>`)

	assert.Contains(t, html, "<li>class.digits</li>")

	assert.Contains(t, html, "<li>dictionary</li>")
}

func TestMarshalHTMLEmptyReport(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "empty-policy",
		Violations:    []ViolationCount{},
		Subjects:      []AuditSubject{},
	}

	data, err := MarshalHTML(report)

	require.NoError(t, err)

	html := string(data)

	assert.Contains(t, html, "<strong>Policy:</strong> empty-policy")

	assert.Contains(t, html, "<p>No violations.</p>")

	assert.Contains(t, html, "<p>No subjects.</p>")

	assert.Contains(t, html, "<td>0</td>")
}

func TestMarshalHTMLEscapesSubject(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "test-policy",
		Violations:    []ViolationCount{},
		Subjects: []AuditSubject{
			{
				Subject: `<script>alert("x")</script>`,
				Passed:  true,
				Rules:   []string{},
			},
		},
	}

	data, err := MarshalHTML(report)

	require.NoError(t, err)

	html := string(data)

	assert.NotContains(t, html, `<script>alert("x")</script>`)

	assert.Contains(t, html, "&lt;script&gt;")

	assert.Contains(t, html, "&lt;/script&gt;")
}

func TestMarshalHTMLEscapesPolicyAndRule(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        `<b>danger</b>`,
		Violations: []ViolationCount{
			{
				Rule:  `<img src=x onerror=alert(1)>`,
				Count: 1,
			},
		},
		Subjects: []AuditSubject{},
	}

	data, err := MarshalHTML(report)

	require.NoError(t, err)

	html := string(data)

	assert.NotContains(t, html, "<b>danger</b>")

	assert.Contains(t, html, "&lt;b&gt;danger&lt;/b&gt;")

	assert.NotContains(t, html, "<img src=x onerror=alert(1)>")

	assert.Contains(t, html, "&lt;img")
}

func TestMarshalHTMLDeterministic(t *testing.T) {
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

	first, err := MarshalHTML(report)
	require.NoError(t, err)

	second, err := MarshalHTML(report)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(first, second), "same report must produce identical HTML bytes")
}

func TestMarshalHTMLEndsWithSingleNewline(t *testing.T) {
	report := AuditReport{
		ReportVersion: 1,
		Policy:        "test-policy",
		Violations:    []ViolationCount{},
		Subjects:      []AuditSubject{},
	}

	data, err := MarshalHTML(report)

	require.NoError(t, err)
	require.NotEmpty(t, data)

	assert.Equal(t, byte('\n'), data[len(data)-1])

	assert.False(t, bytes.HasSuffix(data, []byte{'\n', '\n'}))
}

func TestMarshalHTMLDoesNotContainPasswordField(t *testing.T) {
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

	data, err := MarshalHTML(report)

	require.NoError(t, err)

	html := string(data)

	assert.NotContains(t, html, "password_hash")
	assert.NotContains(t, html, "Password:")
}
