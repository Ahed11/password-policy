package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Ahed11/password-policy/internal/policy"
)

type policyValidationOutput struct {
	Status  string        `json:"status"`
	Version int           `json:"version"`
	Policy  policy.Policy `json:"policy"`
	Issue   policy.Issue  `json:"issue"`
}

func writePolicyValidationResult(w io.Writer, cfg policy.Config) error {
	if w == nil {
		return fmt.Errorf("write policy validation result: writer must not be nil")
	}

	output := policyValidationOutput{
		Status:  "policy is valid",
		Version: cfg.Version,
		Policy:  cfg.Policy,
		Issue:   cfg.Issue,
	}

	encoder := json.NewEncoder(w)

	encoder.SetIndent("", "  ")

	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("write policy validation result: %w", err)
	}

	return nil
}
