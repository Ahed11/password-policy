package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
)

type contextValuesFlag struct {
	values []string
}

// String возвращает строковое представление переданных значений контекста.
func (f *contextValuesFlag) String() string {
	return ""
}

// Set разбирает и добавляет значение контекста из аргумента командной строки.
func (f *contextValuesFlag) Set(value string) error {
	key, contextValue, ok := strings.Cut(value, "=")

	if !ok || key == "" {
		return fmt.Errorf("context must be in key=value form")
	}

	if contextValue == "" {
		return fmt.Errorf("context value for %q must not be empty", key)
	}

	f.values = append(f.values, contextValue)

	return nil
}

func runCheck(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var policyPath string
	var passwordPath string
	var contexts contextValuesFlag

	flags.StringVar(&policyPath, "policy", "", "path to policy file")

	flags.StringVar(&passwordPath, "password-file", "", "password file or - for stdin")

	flags.Var(&contexts, "context", "context value in key=value form")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeCheckUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp check: %v\n", err)

		writeCheckUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp check: unexpected positional argument")

		writeCheckUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp check: --policy is required")

		writeCheckUsage(stderr)

		return exitUsage
	}

	if passwordPath == "" {
		fmt.Fprintln(stderr, "pwp check: --password-file is required")

		writeCheckUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp check: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp check: %v\n", err)

		return exitUsage
	}

	prepared, err := app.Prepare(
		ctx,
		cfg,
		app.PrepareOptions{
			ContextValues: append([]string(nil), contexts.values...),
		},
	)
	if err != nil {
		fmt.Fprintf(stderr, "pwp check: %v\n", err)

		return exitUsage
	}

	password, err := readCheckPassword(passwordPath, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "pwp check: %v\n", err)

		return exitUsage
	}
	defer secret.Zero(password)

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp check: %v\n", err)

		return exitUsage
	}

	evaluation, err := app.Check(ctx, prepared, password)
	if err != nil {
		fmt.Fprintf(stderr, "pwp check: %v\n", err)

		return exitUsage
	}

	if err := writeCheckResult(stdout, cfg.Policy.Name, evaluation); err != nil {
		fmt.Fprintf(stderr, "pwp check: write result: %v\n", err)

		return exitUsage
	}

	if evaluation.Passed {
		return exitSuccess
	}

	return exitFailure
}

func readCheckPassword(path string, stdin io.Reader) ([]byte, error) {
	var (
		password []byte
		err      error
	)

	if path == "-" {
		password, err = io.ReadAll(stdin)
		if err != nil {
			secret.Zero(password)

			return nil, fmt.Errorf("read password from stdin: %w", err)
		}
	} else {
		password, err = os.ReadFile(path)
		if err != nil {
			secret.Zero(password)

			return nil, fmt.Errorf("read password file: %w", err)
		}
	}

	if len(password) >= 2 && password[len(password)-2] == '\r' && password[len(password)-1] == '\n' {
		password = password[:len(password)-2]
	} else if len(password) >= 1 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
	}

	return password, nil
}

func writeCheckResult(w io.Writer, policyName string, evaluation rules.Evaluation) error {
	if evaluation.Passed {
		_, err := fmt.Fprintf(w, "password satisfies policy %q\n", policyName)

		return err
	}

	if _, err := fmt.Fprintf(w, "password does not satisfy policy %q\n", policyName); err != nil {
		return err
	}

	if !evaluation.Length.Passed {
		if _, err := fmt.Fprintf(w, "length FAILED (%d, allowed %d..%d)\n", evaluation.Length.Count, evaluation.Length.Min, evaluation.Length.Max); err != nil {
			return err
		}
	}

	for _, classResult := range evaluation.Classes {
		if classResult.Passed {
			continue
		}

		if _, err := fmt.Fprintf(w, "class %s FAILED (%d, min %d)\n", classResult.Name, classResult.Count, classResult.Minimum); err != nil {
			return err
		}
	}

	for _, violation := range evaluation.Violations {
		if violation.Layout != "" {
			if _, err := fmt.Fprintf(w, "%s FAILED at offset %d, length %d, layout %s\n", violation.Rule, violation.Offset, violation.Length, violation.Layout); err != nil {
				return err
			}

			continue
		}

		if _, err := fmt.Fprintf(w, "%s FAILED at offset %d, length %d\n", violation.Rule, violation.Offset, violation.Length); err != nil {
			return err
		}
	}

	return nil
}

func writeCheckUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp check --policy <file> --password-file <path|-> [--context key=value ...]

Options:
  --policy <file>          Path to policy file
  --password-file <path|-> Password file or - for stdin
  --context key=value      Context value; may be repeated
  -h, --help               Show this help`,
	)
}
