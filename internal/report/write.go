package report

import (
	"errors"
	"fmt"

	"github.com/Ahed11/password-policy/internal/atomicfile"
)

const auditReportFileMode = 0o600

// WriteAudit атомарно записывает JSON- и HTML-версии отчёта аудита в указанные файлы.
func WriteAudit(report AuditReport, jsonPath string, htmlPath string) error {
	if jsonPath == "" {
		return fmt.Errorf("write audit report: JSON path must not be empty")
	}

	if htmlPath == "" {
		return fmt.Errorf("write audit report: HTML path must not be empty")
	}

	if jsonPath == htmlPath {
		return fmt.Errorf("write audit report: JSON and HTML paths must be different")
	}

	jsonData, err := MarshalJSON(report)
	if err != nil {
		return fmt.Errorf("write audit report: prepare JSON: %w", err)
	}

	htmlData, err := MarshalHTML(report)
	if err != nil {
		return fmt.Errorf("write audit report: prepare HTML: %w", err)
	}

	var writeErrors []error

	if err := atomicfile.Write(jsonPath, jsonData, auditReportFileMode); err != nil {
		writeErrors = append(writeErrors, fmt.Errorf("write audit JSON report %q: %w", jsonPath, err))
	}

	if err := atomicfile.Write(htmlPath, htmlData, auditReportFileMode); err != nil {
		writeErrors = append(writeErrors, fmt.Errorf("write audit HTML report %q: %w", htmlPath, err))
	}

	if len(writeErrors) > 0 {
		return errors.Join(writeErrors...)
	}

	return nil
}
