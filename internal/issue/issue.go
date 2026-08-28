package issue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/history"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/secret"
)

var ErrHistoryExhausted = errors.New("history_exhausted")

type Options struct {
	Subject       string
	HistoryWindow int
	RotateAfter   time.Duration
	Now           time.Time
	PolicyName    string
	PolicyVersion string
}

type Result struct {
	Password []byte
	Attempts int
	Record   history.Record
}

func Issue(ctx context.Context, source random.Source, store *history.Store, buildResult alphabet.BuildResult, generateOptions generate.Options, options Options) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("issue password: context must not be nil")
	}

	if source == nil {
		return Result{}, fmt.Errorf("issue password: random source must not be nil")
	}

	if store == nil {
		return Result{}, fmt.Errorf("issue password: history store must not be nil")
	}

	if options.Subject == "" {
		return Result{}, fmt.Errorf("issue password: subject must not be empty")
	}

	if options.HistoryWindow < 0 {
		return Result{}, fmt.Errorf("issue password: history window must not be negative, got %d", options.HistoryWindow)
	}

	if options.RotateAfter < 0 {
		return Result{}, fmt.Errorf("issue password: rotate after must not be negative")
	}

	if generateOptions.Attempts <= 0 {
		return Result{}, fmt.Errorf("issue password: attempts must be greater than zero, got %d", generateOptions.Attempts)
	}

	if options.PolicyName == "" {
		return Result{}, fmt.Errorf("issue password: policy name must not be empty")
	}

	if options.PolicyVersion == "" {
		return Result{}, fmt.Errorf("issue password: policy version must not be empty")
	}

	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("issue password: %w", err)
	}

	issuedAt := options.Now.UTC()

	var expiresAt time.Time

	if options.RotateAfter > 0 {
		expiresAt = issuedAt.Add(options.RotateAfter).UTC()
	}

	historyRejected := false

	for attempt := 1; attempt <= generateOptions.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("issue password: %w", err)
		}

		attemptResult, err := generate.GenerateAttempt(source, buildResult, generateOptions)
		if err != nil {
			return Result{}, fmt.Errorf("issue password on attempt %d: generate candidate: %w", attempt, err)
		}

		if !attemptResult.Accepted {
			continue
		}

		password := attemptResult.Password

		if err := ctx.Err(); err != nil {
			secret.Zero(password)

			return Result{}, fmt.Errorf("issue password on attempt %d: %w", attempt, err)
		}

		salt, err := history.GenerateSalt(source)
		if err != nil {
			secret.Zero(password)

			return Result{}, fmt.Errorf("issue password on attempt %d: generate salt: %w", attempt, err)
		}

		if err := ctx.Err(); err != nil {
			secret.Zero(password)

			return Result{}, fmt.Errorf("issue password on attempt %d: %w", attempt, err)
		}

		hash := history.HashPassword(salt, password)

		record := history.Record{
			Subject:       options.Subject,
			Salt:          salt,
			Hash:          hash,
			IssuedAt:      issuedAt,
			ExpiresAt:     expiresAt,
			PolicyName:    options.PolicyName,
			PolicyVersion: options.PolicyVersion,
		}

		accepted, err := store.Accept(options.Subject, password, options.HistoryWindow, record)
		if err != nil {
			secret.Zero(password)

			return Result{}, fmt.Errorf("issue password on attempt %d: accept history record: %w", attempt, err)
		}

		if !accepted {
			historyRejected = true

			secret.Zero(password)

			continue
		}

		return Result{
			Password: password,
			Attempts: attempt,
			Record:   record,
		}, nil
	}

	if historyRejected {
		return Result{}, fmt.Errorf("%w: exhausted %d attempts", ErrHistoryExhausted, generateOptions.Attempts)
	}

	return Result{}, fmt.Errorf("%w: exhausted %d attempts", generate.ErrPolicyTooStrict, generateOptions.Attempts)
}
