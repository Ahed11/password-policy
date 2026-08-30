package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/atomicfile"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/secret"
)

const generatedPasswordFileMode = 0o600

func runGen(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("gen", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var policyPath string
	var outputPath string
	var count int

	flags.StringVar(&policyPath, "policy", "", "path to policy file")

	flags.IntVar(&count, "count", 1, "number of passwords to generate")

	flags.StringVar(&outputPath, "out", "-", "output file or - for stdout")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeGenUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp gen: %v\n", err)

		writeGenUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp gen: unexpected positional argument")

		writeGenUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp gen: --policy is required")

		writeGenUsage(stderr)

		return exitUsage
	}

	if count <= 0 {
		fmt.Fprintf(stderr, "pwp gen: --count must be greater than zero, got %d\n", count)

		return exitUsage
	}

	if outputPath == "" {
		fmt.Fprintln(stderr, "pwp gen: --out must not be empty")

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp gen: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp gen: %v\n", err)

		return exitUsage
	}

	prepared, err := app.Prepare(ctx, cfg, app.PrepareOptions{})
	if err != nil {
		fmt.Fprintf(stderr, "pwp gen: %v\n", err)

		return exitUsage
	}

	source := random.DefaultSource()

	_, err = app.EvaluateStrength(ctx, source, prepared)
	if err != nil {
		fmt.Fprintf(stderr, "pwp gen: %v\n", err)

		return exitUsage
	}

	results, err := app.Generate(ctx, source, prepared, count)
	if err != nil {
		fmt.Fprintf(stderr, "pwp gen: %v\n", err)

		return exitUsage
	}

	defer zeroGenerationResults(results)

	data := marshalGeneratedPasswords(results)
	defer secret.Zero(data)

	if outputPath == "-" {
		if err := writeGeneratedPasswords(stdout, data); err != nil {
			fmt.Fprintf(stderr, "pwp gen: write stdout: %v\n", err)

			return exitUsage
		}

		return exitSuccess
	}

	if err := atomicfile.Write(outputPath, data, generatedPasswordFileMode); err != nil {
		fmt.Fprintf(stderr, "pwp gen: %v\n", err)

		return exitUsage
	}

	return exitSuccess
}

func marshalGeneratedPasswords(results []app.GenerationResult) []byte {
	size := len(results)

	for i := range results {
		size += len(results[i].Password)
	}

	data := make([]byte, 0, size)

	for i := range results {
		data = append(data, results[i].Password...)

		data = append(data, '\n')
	}

	return data
}

func zeroGenerationResults(results []app.GenerationResult) {
	for i := range results {
		secret.Zero(results[i].Password)
	}
}

func writeGeneratedPasswords(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

func writeGenUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp gen --policy <file> [--count <n>] [--out <path|->]

Options:
  --policy <file>   Path to policy file
  --count <n>       Number of passwords to generate (default 1)
  --out <path|->    Output file or - for stdout (default -)
  -h, --help        Show this help`,
	)
}
