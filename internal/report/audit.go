package report

import (
	"sort"

	"github.com/Ahed11/password-policy/internal/app"
)

const auditReportVersion = 1

type AuditReport struct {
	ReportVersion int              `json:"report_version"`
	Policy        string           `json:"policy"`
	Totals        AuditTotals      `json:"totals"`
	Violations    []ViolationCount `json:"violations"`
	Subjects      []AuditSubject   `json:"subjects"`
}

type AuditTotals struct {
	Checked int `json:"checked"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
}

type ViolationCount struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

type AuditSubject struct {
	Subject string   `json:"subject"`
	Passed  bool     `json:"passed"`
	Rules   []string `json:"rules"`
}

func BuildAudit(result app.AuditResult) AuditReport {
	report := AuditReport{
		ReportVersion: auditReportVersion,
		Policy:        result.Policy,
		Totals: AuditTotals{
			Checked: result.Checked,
			Passed:  result.Passed,
			Failed:  result.Failed,
		},
		Violations: make([]ViolationCount, 0),
		Subjects:   make([]AuditSubject, 0, len(result.Subjects)),
	}

	ruleCounts := make(map[string]int)

	for _, subject := range result.Subjects {
		rulesCopy := make([]string, 0, len(subject.Rules))

		seen := make(map[string]struct{}, len(subject.Rules))

		for _, rule := range subject.Rules {
			if _, exists := seen[rule]; exists {
				continue
			}

			seen[rule] = struct{}{}

			rulesCopy = append(rulesCopy, rule)

			ruleCounts[rule]++
		}

		report.Subjects = append(
			report.Subjects,
			AuditSubject{
				Subject: subject.Subject,
				Passed:  subject.Passed,
				Rules:   rulesCopy,
			},
		)
	}

	report.Violations = make([]ViolationCount, 0, len(ruleCounts))

	for rule, count := range ruleCounts {
		report.Violations = append(
			report.Violations,
			ViolationCount{
				Rule:  rule,
				Count: count,
			},
		)
	}

	sort.Slice(
		report.Violations,
		func(i, j int) bool {
			return report.Violations[i].Rule < report.Violations[j].Rule
		},
	)

	return report
}
