package report

import (
	"fmt"
	"testing"
)

var benchmarkSerializedReport []byte

func BenchmarkSerializeAuditReport(b *testing.B) {
	report := benchmarkAuditReport(1204)

	b.Run(
		"json",
		func(b *testing.B) {
			benchmarkMarshalJSON(b, report)
		},
	)

	b.Run(
		"html",
		func(b *testing.B) {
			benchmarkMarshalHTML(b, report)
		},
	)
}

func benchmarkMarshalJSON(b *testing.B, report AuditReport) {
	b.Helper()

	data, err := MarshalJSON(report)
	if err != nil {
		b.Fatalf("marshal benchmark JSON report: %v", err)
	}

	if len(data) == 0 {
		b.Fatal("benchmark JSON report must not be empty")
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, err := MarshalJSON(report)
		if err != nil {
			b.Fatal(err)
		}

		benchmarkSerializedReport = data
	}
}

func benchmarkMarshalHTML(b *testing.B, report AuditReport) {
	b.Helper()

	data, err := MarshalHTML(report)
	if err != nil {
		b.Fatalf("marshal benchmark HTML report: %v", err)
	}

	if len(data) == 0 {
		b.Fatal("benchmark HTML report must not be empty")
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, err := MarshalHTML(report)
		if err != nil {
			b.Fatal(err)
		}

		benchmarkSerializedReport = data
	}
}

func benchmarkAuditReport(subjectCount int) AuditReport {
	subjects := make([]AuditSubject, 0, subjectCount)

	failed := 0

	for i := 0; i < subjectCount; i++ {
		subject := AuditSubject{
			Subject: fmt.Sprintf("svc-%04d", i+1),
			Passed:  true,
			Rules:   []string{},
		}

		switch i % 7 {
		case 0:
			subject.Passed = false
			subject.Rules = []string{
				"class.special",
				"dictionary",
			}

		case 1:
			subject.Passed = false
			subject.Rules = []string{
				"length",
			}

		case 2:
			subject.Passed = false
			subject.Rules = []string{
				"sequences.keyboard",
			}
		}

		if !subject.Passed {
			failed++
		}

		subjects = append(subjects, subject)
	}

	return AuditReport{
		ReportVersion: 1,
		Policy:        "service-accounts",
		Totals: AuditTotals{
			Checked: subjectCount,
			Passed:  subjectCount - failed,
			Failed:  failed,
		},
		Violations: []ViolationCount{
			{
				Rule:  "class.special",
				Count: 172,
			},
			{
				Rule:  "dictionary",
				Count: 172,
			},
			{
				Rule:  "length",
				Count: 172,
			},
			{
				Rule:  "sequences.keyboard",
				Count: 172,
			},
		},
		Subjects: subjects,
	}
}
