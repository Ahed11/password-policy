package app

import (
	"context"
	"fmt"

	"github.com/Ahed11/password-policy/internal/rules"
)

type RuleExplanation struct {
	Rule       string
	Passed     bool
	Violations []rules.Violation
}

type Explanation struct {
	Passed  bool
	Length  rules.LengthResult
	Classes []rules.ClassResult
	Rules   []RuleExplanation
}

func Explain(ctx context.Context, prepared Prepared, password []byte) (Explanation, error) {
	if ctx == nil {
		return Explanation{}, fmt.Errorf("explain password: context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return Explanation{}, fmt.Errorf("explain password: %w", err)
	}

	evaluation, err := Check(ctx, prepared, password)
	if err != nil {
		return Explanation{}, fmt.Errorf("explain password: %w", err)
	}

	result := Explanation{
		Passed:  evaluation.Passed,
		Length:  evaluation.Length,
		Classes: append([]rules.ClassResult(nil), evaluation.Classes...),
	}

	ruleOrder := [...]string{
		"repeat_run",
		"repeat_total",
		"sequences.alphabet",
		"sequences.keyboard",
		"dictionary",
		"context",
	}

	result.Rules = make([]RuleExplanation, 0, len(ruleOrder))

	for _, ruleName := range ruleOrder {
		explanation := RuleExplanation{
			Rule:   ruleName,
			Passed: true,
		}

		for _, violation := range evaluation.Violations {
			if violation.Rule != ruleName {
				continue
			}

			explanation.Passed = false
			explanation.Violations = append(explanation.Violations, violation)
		}

		result.Rules = append(result.Rules, explanation)
	}

	if err := ctx.Err(); err != nil {
		return Explanation{}, fmt.Errorf("explain password: %w", err)
	}

	return result, nil
}
