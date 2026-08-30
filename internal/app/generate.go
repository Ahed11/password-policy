package app

import (
	"context"
	"fmt"

	generator "github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/secret"
)

// GenerationResult содержит сгенерированный пароль и количество использованных попыток.
type GenerationResult struct {
	Password []byte
	Attempts int
}

// Generate создаёт заданное количество паролей по подготовленной политике.
func Generate(ctx context.Context, source random.Source, prepared Prepared, count int) ([]GenerationResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("generate passwords: context must not be nil")
	}

	if source == nil {
		return nil, fmt.Errorf("generate passwords: random source must not be nil")
	}

	if count <= 0 {
		return nil, fmt.Errorf("generate passwords: count must be greater than zero, got %d", count)
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("generate passwords: %w", err)
	}

	results := make([]GenerationResult, 0, count)

	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			zeroGenerationResults(results)

			return nil, fmt.Errorf("generate password %d of %d: %w", i+1, count, err)
		}

		result, err := generator.Generate(source, prepared.Alphabet, prepared.Generate)
		if err != nil {
			if result.Password != nil {
				secret.Zero(result.Password)
			}

			zeroGenerationResults(results)

			return nil, fmt.Errorf("generate password %d of %d: %w", i+1, count, err)
		}

		results = append(
			results,
			GenerationResult{
				Password: result.Password,
				Attempts: result.Attempts,
			},
		)

		if err := ctx.Err(); err != nil {
			zeroGenerationResults(results)

			return nil, fmt.Errorf("generate password %d of %d: %w", i+1, count, err)
		}
	}

	return results, nil
}

func zeroGenerationResults(results []GenerationResult) {
	for i := range results {
		secret.Zero(results[i].Password)
	}
}
