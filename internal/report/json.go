package report

import (
	"encoding/json"
	"fmt"
)

func MarshalJSON(report AuditReport) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal audit report JSON: %w", err)
	}

	data = append(data, '\n')

	return data, nil
}
