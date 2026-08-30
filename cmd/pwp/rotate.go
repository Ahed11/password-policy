package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/Ahed11/password-policy/internal/history"
	"github.com/Ahed11/password-policy/internal/policy"
)

func runRotate(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("rotate", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var policyPath string
	var storePath string
	var nowValue string
	var strict bool

	flags.StringVar(&policyPath, "policy", "", "path to policy file")

	flags.StringVar(&storePath, "store", "", "history store directory")

	flags.StringVar(&nowValue, "now", "", "current time in RFC3339 format")

	flags.BoolVar(&strict, "strict", false, "treat warnings as errors")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeRotateUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp rotate: %v\n", err)

		writeRotateUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp rotate: unexpected positional argument")

		writeRotateUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp rotate: --policy is required")

		writeRotateUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp rotate: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp rotate: %v\n", err)

		return exitUsage
	}

	if storePath == "" {
		storePath = cfg.Issue.Store
	}

	if storePath == "" {
		fmt.Fprintln(stderr, "pwp rotate: --store is required when issue.store is empty")

		writeRotateUsage(stderr)

		return exitUsage
	}

	now := time.Now().UTC()

	if nowValue != "" {
		parsedNow, err := time.Parse(time.RFC3339, nowValue)
		if err != nil {
			fmt.Fprintf(stderr, "pwp rotate: invalid --now value %q: %v\n", nowValue, err)

			return exitUsage
		}

		now = parsedNow.UTC()
	}

	store, err := history.Open(storePath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp rotate: %v\n", err)

		return exitUsage
	}

	plan, planErr := store.PlanRotation(now)

	closeErr := store.Close()

	if planErr != nil || closeErr != nil {
		err := errors.Join(planErr, closeErr)

		fmt.Fprintf(stderr, "pwp rotate: %v\n", err)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp rotate: %v\n", err)

		return exitUsage
	}

	data, err := marshalRotationPlan(plan)
	if err != nil {
		fmt.Fprintf(stderr, "pwp rotate: %v\n", err)

		return exitUsage
	}

	if err := writeRotationPlan(stdout, data); err != nil {
		fmt.Fprintf(stderr, "pwp rotate: write stdout: %v\n", err)

		return exitUsage
	}

	if strict && len(plan.Warnings) > 0 {
		return exitUsage
	}

	if len(plan.Items) > 0 {
		return exitFailure
	}

	return exitSuccess
}

func marshalRotationPlan(plan history.RotationPlan) ([]byte, error) {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode rotation plan: %w", err)
	}

	data = append(data, '\n')

	return data, nil
}

func writeRotationPlan(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

func writeRotateUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp rotate --policy <file> [--store <dir>] [--now <RFC3339>] [--strict]

Options:
  --policy <file>   Path to policy file
  --store <dir>     History store directory; overrides issue.store
  --now <RFC3339>   Current time; defaults to system time
  --strict          Treat warnings as errors
  -h, --help        Show this help`,
	)
}
