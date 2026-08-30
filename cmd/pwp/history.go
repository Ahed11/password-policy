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

type historyOutputRecord struct {
	Subject       string    `json:"subject"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	PolicyName    string    `json:"policy_name"`
	PolicyVersion string    `json:"policy_version"`
}

func runHistory(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("history", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var subject string
	var storePath string

	flags.StringVar(&subject, "subject", "", "subject whose history to show")

	flags.StringVar(&storePath, "store", "", "history store directory")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeHistoryUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp history: %v\n", err)

		writeHistoryUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp history: unexpected positional argument")

		writeHistoryUsage(stderr)

		return exitUsage
	}

	if subject == "" {
		fmt.Fprintln(stderr, "pwp history: --subject is required")

		writeHistoryUsage(stderr)

		return exitUsage
	}

	if storePath == "" {
		fmt.Fprintln(stderr, "pwp history: --store is required")

		writeHistoryUsage(stderr)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp history: %v\n", err)

		return exitUsage
	}

	store, err := history.Open(storePath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp history: %v\n", err)

		return exitUsage
	}

	records, listErr := store.List(subject)

	closeErr := store.Close()

	if listErr != nil || closeErr != nil {
		err := errors.Join(listErr, closeErr)

		fmt.Fprintf(stderr, "pwp history: %v\n", err)

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp history: %v\n", err)

		return exitUsage
	}

	data, err := marshalHistoryRecords(records)
	if err != nil {
		fmt.Fprintf(stderr, "pwp history: %v\n", err)

		return exitUsage
	}

	if err := writeHistoryOutput(stdout, data); err != nil {
		fmt.Fprintf(stderr, "pwp history: write stdout: %v\n", err)

		return exitUsage
	}

	return exitSuccess
}

func marshalHistoryRecords(records []history.Record) ([]byte, error) {
	output := make([]historyOutputRecord, 0, len(records))

	for _, record := range records {
		output = append(
			output,
			historyOutputRecord{
				Subject:       record.Subject,
				IssuedAt:      record.IssuedAt,
				ExpiresAt:     record.ExpiresAt,
				PolicyName:    record.PolicyName,
				PolicyVersion: record.PolicyVersion,
			},
		)
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode history output: %w", err)
	}

	data = append(data, '\n')

	return data, nil
}

func writeHistoryOutput(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

func writeHistoryUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp history --subject <subject> --store <dir>

Options:
  --subject <subject>   Subject whose history to show
  --store <dir>         History store directory
  -h, --help            Show this help`,
	)
}
