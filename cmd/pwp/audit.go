package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/report"
)

func runAudit(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var policyPath string
	var inputPath string
	var reportPath string
	var reportHTMLPath string
	var strict bool

	flags.StringVar(&policyPath, "policy", "", "path to policy file")

	flags.StringVar(&inputPath, "input", "", "input JSONL file or - for stdin")

	flags.StringVar(&reportPath, "report", "", "path to JSON audit report")

	flags.StringVar(&reportHTMLPath, "report-html", "", "path to HTML audit report")

	flags.BoolVar(&strict, "strict", false, "treat audit warnings as errors")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeAuditUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp audit: %v\n", err)

		writeAuditUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp audit: unexpected positional argument")

		writeAuditUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp audit: --policy is required")

		writeAuditUsage(stderr)

		return exitUsage
	}

	if inputPath == "" {
		fmt.Fprintln(stderr, "pwp audit: --input is required")

		writeAuditUsage(stderr)

		return exitUsage
	}

	if reportPath == "" {
		fmt.Fprintln(stderr, "pwp audit: --report is required")

		writeAuditUsage(stderr)

		return exitUsage
	}

	if reportHTMLPath == "" {
		fmt.Fprintln(stderr, "pwp audit: --report-html is required")

		writeAuditUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp audit: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp audit: %v\n", err)

		return exitUsage
	}

	prepared, err := app.Prepare(ctx, cfg, app.PrepareOptions{})
	if err != nil {
		fmt.Fprintf(stderr, "pwp audit: %v\n", err)

		return exitUsage
	}

	input, closeInput, err := openAuditInput(inputPath, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "pwp audit: %v\n", err)

		return exitUsage
	}

	auditResult, auditErr := app.Audit(
		ctx,
		input,
		prepared,
		app.AuditOptions{
			Strict: strict,
		},
	)

	closeErr := closeInput()

	if auditErr != nil {
		fmt.Fprintf(stderr, "pwp audit: %v\n", auditErr)

		if closeErr != nil {
			fmt.Fprintf(stderr, "pwp audit: close input: %v\n", closeErr)
		}

		return exitUsage
	}

	if closeErr != nil {
		fmt.Fprintf(stderr, "pwp audit: close input: %v\n", closeErr)

		return exitUsage
	}

	for _, lineError := range auditResult.LineErrors {
		fmt.Fprintf(stderr, "pwp audit: warning: line %d: %s\n", lineError.Line, lineError.Message)
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp audit: %v\n", err)

		return exitUsage
	}

	auditReport := report.BuildAudit(auditResult)

	if err := report.WriteAudit(auditReport, reportPath, reportHTMLPath); err != nil {
		fmt.Fprintf(stderr, "pwp audit: %v\n", err)

		return exitUsage
	}

	if err := writeAuditSummary(stdout, auditResult); err != nil {
		fmt.Fprintf(stderr, "pwp audit: write result: %v\n", err)

		return exitUsage
	}

	if auditResult.Failed > 0 {
		return exitFailure
	}

	return exitSuccess
}

func openAuditInput(path string, stdin io.Reader) (io.Reader, func() error, error) {
	if path == "-" {
		return stdin, func() error {
			return nil
		}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit input %q: %w", path, err)
	}

	return file, file.Close, nil
}

func writeAuditSummary(w io.Writer, result app.AuditResult) error {
	if w == nil {
		return fmt.Errorf("writer must not be nil")
	}

	_, err := fmt.Fprintf(w, "audit: checked=%d passed=%d failed=%d warnings=%d\n", result.Checked, result.Passed, result.Failed, len(result.LineErrors))

	return err
}

func writeAuditUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp audit --policy <file> --input <jsonl|-> --report <file> --report-html <file> [--strict]

Options:
  --policy <file>       Path to policy file
  --input <jsonl|->     Input JSONL file or - for stdin
  --report <file>       Path to JSON audit report
  --report-html <file>  Path to HTML audit report
  --strict              Treat warnings as errors
  -h, --help            Show this help`,
	)
}
