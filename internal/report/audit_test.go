package report

import (
	"testing"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/stretchr/testify/assert"
)

func TestBuildAuditEmpty(t *testing.T) {
	result := app.AuditResult{
		Policy: "test-policy",
	}

	got := BuildAudit(result)

	assert.Equal(t, AuditReport{
		ReportVersion: 1,
		Policy:        "test-policy",
		Totals: AuditTotals{
			Checked: 0,
			Passed:  0,
			Failed:  0,
		},
		Violations: []ViolationCount{},
		Subjects:   []AuditSubject{},
	}, got)
}

func TestBuildAudit(t *testing.T) {
	result := app.AuditResult{
		Policy:  "service-accounts",
		Checked: 3,
		Passed:  1,
		Failed:  2,
		Subjects: []app.AuditSubject{
			{
				Subject: "svc-02",
				Passed:  false,
				Rules: []string{
					"dictionary",
					"class.digits",
				},
			},
			{
				Subject: "svc-01",
				Passed:  false,
				Rules: []string{
					"dictionary",
					"repeat_run",
				},
			},
			{
				Subject: "svc-03",
				Passed:  true,
			},
		},
	}

	got := BuildAudit(result)

	assert.Equal(t, 1, got.ReportVersion)
	assert.Equal(t, "service-accounts", got.Policy)

	assert.Equal(t, AuditTotals{
		Checked: 3,
		Passed:  1,
		Failed:  2,
	}, got.Totals)

	assert.Equal(t, []ViolationCount{
		{
			Rule:  "class.digits",
			Count: 1,
		},
		{
			Rule:  "dictionary",
			Count: 2,
		},
		{
			Rule:  "repeat_run",
			Count: 1,
		},
	}, got.Violations)

	assert.Equal(t, []AuditSubject{
		{
			Subject: "svc-02",
			Passed:  false,
			Rules: []string{
				"dictionary",
				"class.digits",
			},
		},
		{
			Subject: "svc-01",
			Passed:  false,
			Rules: []string{
				"dictionary",
				"repeat_run",
			},
		},
		{
			Subject: "svc-03",
			Passed:  true,
			Rules:   []string{},
		},
	}, got.Subjects)
}

func TestBuildAuditCountsRuleOncePerSubject(t *testing.T) {
	result := app.AuditResult{
		Policy:  "test-policy",
		Checked: 2,
		Failed:  2,
		Subjects: []app.AuditSubject{
			{
				Subject: "svc-01",
				Passed:  false,
				Rules: []string{
					"dictionary",
					"dictionary",
					"repeat_run",
					"dictionary",
				},
			},
			{
				Subject: "svc-02",
				Passed:  false,
				Rules: []string{
					"dictionary",
				},
			},
		},
	}

	got := BuildAudit(result)

	assert.Equal(t, []ViolationCount{
		{
			Rule:  "dictionary",
			Count: 2,
		},
		{
			Rule:  "repeat_run",
			Count: 1,
		},
	}, got.Violations)

	assert.Equal(t, []string{
		"dictionary",
		"repeat_run",
	}, got.Subjects[0].Rules)

	assert.Equal(t, []string{
		"dictionary",
	}, got.Subjects[1].Rules)
}

func TestBuildAuditSortsViolationsByRule(t *testing.T) {
	result := app.AuditResult{
		Subjects: []app.AuditSubject{
			{
				Subject: "svc-01",
				Passed:  false,
				Rules: []string{
					"repeat_total",
					"length",
					"dictionary",
					"class.special",
					"context",
				},
			},
		},
	}

	got := BuildAudit(result)

	assert.Equal(t, []ViolationCount{
		{
			Rule:  "class.special",
			Count: 1,
		},
		{
			Rule:  "context",
			Count: 1,
		},
		{
			Rule:  "dictionary",
			Count: 1,
		},
		{
			Rule:  "length",
			Count: 1,
		},
		{
			Rule:  "repeat_total",
			Count: 1,
		},
	}, got.Violations)
}

func TestBuildAuditPreservesSubjectOrder(t *testing.T) {
	result := app.AuditResult{
		Subjects: []app.AuditSubject{
			{
				Subject: "svc-03",
				Passed:  true,
			},
			{
				Subject: "svc-01",
				Passed:  true,
			},
			{
				Subject: "svc-02",
				Passed:  true,
			},
		},
	}

	got := BuildAudit(result)

	assert.Equal(t, "svc-03", got.Subjects[0].Subject)
	assert.Equal(t, "svc-01", got.Subjects[1].Subject)
	assert.Equal(t, "svc-02", got.Subjects[2].Subject)
}

func TestBuildAuditCopiesSubjectRules(t *testing.T) {
	rules := []string{
		"dictionary",
		"repeat_run",
	}

	result := app.AuditResult{
		Subjects: []app.AuditSubject{
			{
				Subject: "svc-01",
				Passed:  false,
				Rules:   rules,
			},
		},
	}

	got := BuildAudit(result)

	rules[0] = "changed"

	assert.Equal(t, []string{
		"dictionary",
		"repeat_run",
	}, got.Subjects[0].Rules)
}
