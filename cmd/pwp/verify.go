package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Ahed11/password-policy/internal/history"
)

func runVerify(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var storePath string

	flags.StringVar(&storePath, "store", "", "history store directory")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeVerifyUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp verify: %v\n", err)

		writeVerifyUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp verify: unexpected positional argument")

		writeVerifyUsage(stderr)

		return exitUsage
	}

	if storePath == "" {
		fmt.Fprintln(stderr, "pwp verify: --store is required")

		writeVerifyUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp verify: %v\n", err)

		return exitUsage
	}

	store, err := history.Open(storePath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp verify: %v\n", err)

		return exitUsage
	}

	result, verifyErr := store.Verify()

	closeErr := store.Close()

	if verifyErr != nil || closeErr != nil {
		err := errors.Join(verifyErr, closeErr)

		fmt.Fprintf(stderr, "pwp verify: %v\n", err)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp verify: %v\n", err)

		return exitUsage
	}

	data, err := marshalVerifyResult(result)
	if err != nil {
		fmt.Fprintf(stderr, "pwp verify: %v\n", err)

		return exitUsage
	}

	if err := writeVerifyOutput(stdout, data); err != nil {
		fmt.Fprintf(stderr, "pwp verify: write stdout: %v\n", err)

		return exitUsage
	}

	if len(result.Issues) > 0 {
		return exitFailure
	}

	return exitSuccess
}

func marshalVerifyResult(result history.VerifyResult) ([]byte, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode verify result: %w", err)
	}

	data = append(data, '\n')

	return data, nil
}

func writeVerifyOutput(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

func writeVerifyUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp verify --store <dir>

Options:
  --store <dir>   History store directory
  -h, --help      Show this help`,
	)
}
