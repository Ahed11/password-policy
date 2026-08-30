package app

import (
	"context"
	"fmt"

	"github.com/Ahed11/password-policy/internal/rules"
)

// Check проверяет пароль по подготовленной политике и возвращает результат оценки правил.
func Check(ctx context.Context, prepared Prepared, password []byte) (rules.Evaluation, error) {
	if ctx == nil {
		return rules.Evaluation{}, fmt.Errorf("check password: context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return rules.Evaluation{}, fmt.Errorf("check password: %w", err)
	}

	evaluation, err := rules.Evaluate(
		password,
		prepared.Alphabet,
		rules.EvaluationOptions{
			MinLength:     prepared.Generate.MinLength,
			MaxLength:     prepared.Generate.MaxLength,
			ClassMinimums: prepared.ClassMinimums,
			Rules:         prepared.Rules,
		},
	)
	if err != nil {
		return rules.Evaluation{}, fmt.Errorf("check password against policy: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return rules.Evaluation{}, fmt.Errorf("check password: %w", err)
	}

	return evaluation, nil
}
