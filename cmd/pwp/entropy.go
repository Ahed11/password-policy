package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/random"
)

func runEntropy(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("entropy", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var policyPath string

	flags.StringVar(&policyPath, "policy", "", "path to policy file")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeEntropyUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp entropy: %v\n", err)

		writeEntropyUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp entropy: unexpected positional argument")

		writeEntropyUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp entropy: --policy is required")

		writeEntropyUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp entropy: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp entropy: %v\n", err)

		return exitUsage
	}

	prepared, err := app.Prepare(ctx, cfg, app.PrepareOptions{})
	if err != nil {
		fmt.Fprintf(stderr, "pwp entropy: %v\n", err)

		return exitUsage
	}

	source := random.DefaultSource()

	estimate, err := app.EvaluateStrength(ctx, source, prepared)
	if err != nil {
		fmt.Fprintf(stderr, "pwp entropy: %v\n", err)

		return exitUsage
	}

	output := fmt.Sprintf("%.1f bits (lower bound)\n", estimate.Bits)

	written, err := io.WriteString(stdout, output)
	if err != nil {
		fmt.Fprintf(stderr, "pwp entropy: write stdout: %v\n", err)

		return exitFailure
	}

	if written != len(output) {
		fmt.Fprintf(stderr, "pwp entropy: write stdout: %v\n", io.ErrShortWrite)

		return exitFailure
	}

	return exitSuccess
}

func writeEntropyUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp entropy --policy <file>

Options:
  --policy <file>   Path to policy file
  -h, --help        Show this help`,
	)
}
