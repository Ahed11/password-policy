package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/policy"
)

func runPolicy(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		writePolicyUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		writePolicyUsage(stdout)
		return exitSuccess

	case "validate":
		return runPolicyValidate(ctx, args[1:], stdout, stderr)

	default:
		fmt.Fprintf(stderr, "pwp policy: unknown command %q\n", args[0])

		writePolicyUsage(stderr)

		return exitUsage
	}
}

func runPolicyValidate(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy validate", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var policyPath string

	flags.StringVar(&policyPath, "policy", "", "path to policy file")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writePolicyValidateUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp policy validate: %v\n", err)

		writePolicyValidateUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp policy validate: unexpected positional argument")

		writePolicyValidateUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp policy validate: --policy is required")

		writePolicyValidateUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp policy validate: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp policy validate: %v\n", err)

		return exitUsage
	}

	prepared, err := app.Prepare(ctx, cfg, app.PrepareOptions{})
	if err != nil {
		fmt.Fprintf(stderr, "pwp policy validate: %v\n", err)

		return exitUsage
	}

	_, err = app.EvaluateStrengthDeterministic(ctx, prepared)
	if err != nil {
		fmt.Fprintf(stderr, "pwp policy validate: %v\n", err)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp policy validate: %v\n", err)

		return exitUsage
	}

	if err := writePolicyValidationResult(stdout, cfg); err != nil {
		fmt.Fprintf(stderr, "pwp policy validate: %v\n", err)

		return exitFailure
	}

	return exitSuccess
}

func writePolicyUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp policy <command> [options]

Commands:
  validate   Validate a policy file

Options:
  -h, --help   Show this help`,
	)
}

func writePolicyValidateUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp policy validate --policy <file>

Options:
  --policy <file>   Path to policy file
  -h, --help        Show this help`,
	)
}
