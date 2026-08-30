package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/secret"
)

func runExplain(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("explain", flag.ContinueOnError)

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
			writeExplainUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp explain: %v\n", err)

		writeExplainUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp explain: unexpected positional argument")

		writeExplainUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp explain: --policy is required")

		writeExplainUsage(stderr)

		return exitUsage
	}

	if passwordPath == "" {
		fmt.Fprintln(stderr, "pwp explain: --password-file is required")

		writeExplainUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp explain: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp explain: %v\n", err)

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
		fmt.Fprintf(stderr, "pwp explain: %v\n", err)

		return exitUsage
	}

	password, err := readCheckPassword(passwordPath, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "pwp explain: %v\n", err)

		return exitUsage
	}
	defer secret.Zero(password)

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp explain: %v\n", err)

		return exitUsage
	}

	explanation, err := app.Explain(ctx, prepared, password)
	if err != nil {
		fmt.Fprintf(stderr, "pwp explain: %v\n", err)

		return exitUsage
	}

	if err := writeExplainResult(stdout, cfg.Policy.Name, explanation); err != nil {
		fmt.Fprintf(stderr, "pwp explain: write result: %v\n", err)

		return exitUsage
	}

	if explanation.Passed {
		return exitSuccess
	}

	return exitFailure
}

func writeExplainResult(w io.Writer, policyName string, explanation app.Explanation) error {
	if w == nil {
		return fmt.Errorf("writer must not be nil")
	}

	if _, err := fmt.Fprintf(w, "policy: %q\n", policyName); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "passed: %s\n", passFail(explanation.Passed)); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "length: %s (count %d, allowed %d..%d)\n", passFail(explanation.Length.Passed), explanation.Length.Count, explanation.Length.Min, explanation.Length.Max); err != nil {
		return err
	}

	for _, classResult := range explanation.Classes {
		if _, err := fmt.Fprintf(w, "class %s: %s (count %d, min %d)\n", classResult.Name, passFail(classResult.Passed), classResult.Count, classResult.Minimum); err != nil {
			return err
		}
	}

	for _, ruleResult := range explanation.Rules {
		if _, err := fmt.Fprintf(w, "rule %s: %s\n", ruleResult.Rule, passFail(ruleResult.Passed)); err != nil {
			return err
		}

		for _, violation := range ruleResult.Violations {
			if violation.Layout != "" {
				if _, err := fmt.Fprintf(w, "  violation: offset %d, length %d, layout %s\n", violation.Offset, violation.Length, violation.Layout); err != nil {
					return err
				}

				continue
			}

			if _, err := fmt.Fprintf(w, "  violation: offset %d, length %d\n", violation.Offset, violation.Length); err != nil {
				return err
			}
		}
	}

	return nil
}

func passFail(passed bool) string {
	if passed {
		return "PASS"
	}

	return "FAIL"
}

func writeExplainUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp explain --policy <file> --password-file <path|-> [--context key=value ...]

Options:
  --policy <file>          Path to policy file
  --password-file <path|-> Password file or - for stdin
  --context key=value      Context value; may be repeated
  -h, --help               Show this help`,
	)
}
