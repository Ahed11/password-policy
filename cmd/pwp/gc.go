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
)

type gcOutput struct {
	Deleted int `json:"deleted"`
	Kept    int `json:"kept"`
}

func runGC(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("gc", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var storePath string
	var nowValue string

	flags.StringVar(&storePath, "store", "", "history store directory")

	flags.StringVar(&nowValue, "now", "", "current time in RFC3339 format")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeGCUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp gc: %v\n", err)

		writeGCUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp gc: unexpected positional argument")

		writeGCUsage(stderr)

		return exitUsage
	}

	if storePath == "" {
		fmt.Fprintln(stderr, "pwp gc: --store is required")

		writeGCUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp gc: %v\n", err)

		return exitUsage
	}

	now := time.Now().UTC()

	if nowValue != "" {
		parsedNow, err := time.Parse(time.RFC3339, nowValue)
		if err != nil {
			fmt.Fprintf(stderr, "pwp gc: invalid --now value %q: %v\n", nowValue, err)

			return exitUsage
		}

		now = parsedNow.UTC()
	}

	store, err := history.Open(storePath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp gc: %v\n", err)

		return exitUsage
	}

	metadata, metadataErr := store.LoadMetadata()
	if metadataErr != nil {
		closeErr := store.Close()

		err := errors.Join(metadataErr, closeErr)

		fmt.Fprintf(stderr, "pwp gc: %v\n", err)

		return exitUsage
	}

	result, gcErr := store.GC(
		now,
		metadata.HistoryTTL,
		metadata.HistoryWindow,
	)

	closeErr := store.Close()

	if gcErr != nil || closeErr != nil {
		err := errors.Join(gcErr, closeErr)

		fmt.Fprintf(stderr, "pwp gc: %v\n", err)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp gc: %v\n", err)

		return exitUsage
	}

	data, err := marshalGCResult(result)
	if err != nil {
		fmt.Fprintf(stderr, "pwp gc: %v\n", err)

		return exitUsage
	}

	if err := writeGCOutput(stdout, data); err != nil {
		fmt.Fprintf(stderr, "pwp gc: write stdout: %v\n", err)

		return exitUsage
	}

	return exitSuccess
}

func marshalGCResult(result history.GCResult) ([]byte, error) {
	output := gcOutput{
		Deleted: result.Deleted,
		Kept:    result.Kept,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode gc result: %w", err)
	}

	data = append(data, '\n')

	return data, nil
}

func writeGCOutput(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

func writeGCUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp gc --store <dir> [--now <RFC3339>]

Options:
  --store <dir>     History store directory
  --now <RFC3339>   Current time; defaults to system time
  -h, --help        Show this help`,
	)
}
