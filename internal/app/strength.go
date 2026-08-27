package app

import (
	"context"
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/strength"
)

func EvaluateStrength(ctx context.Context, source random.Source, prepared Prepared) (strength.Estimate, error) {
	if ctx == nil {
		return strength.Estimate{}, fmt.Errorf("evaluate strength: context must not be nil")
	}

	if source == nil {
		return strength.Estimate{}, fmt.Errorf("evaluate strength: random source must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return strength.Estimate{}, fmt.Errorf("evaluate strength: %w", err)
	}

	estimate, err := strength.EstimateEntropy(source, prepared.Alphabet, prepared.Generate)
	if err != nil {
		return strength.Estimate{}, fmt.Errorf("evaluate policy strength: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return strength.Estimate{}, fmt.Errorf("evaluate strength: %w", err)
	}

	window := prepared.Config.Issue.History.Window

	if err := strength.CheckHistoryWindow(estimate.Bits, window); err != nil {
		return estimate, fmt.Errorf("check history window solvability: %w", err)
	}

	return estimate, nil
}
