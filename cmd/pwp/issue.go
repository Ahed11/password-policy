package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/Ahed11/password-policy/internal/app"
	"github.com/Ahed11/password-policy/internal/atomicfile"
	"github.com/Ahed11/password-policy/internal/history"
	"github.com/Ahed11/password-policy/internal/issue"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/secret"
)

const issuedPasswordFileMode = 0o600

func runIssue(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("issue", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var policyPath string
	var subject string
	var storePath string
	var outputPath string
	var nowValue string

	flags.StringVar(&policyPath, "policy", "", "path to policy file")

	flags.StringVar(&subject, "subject", "", "subject to issue password for")

	flags.StringVar(&storePath, "store", "", "history store directory")

	flags.StringVar(&outputPath, "out", "-", "output file or - for stdout")

	flags.StringVar(&nowValue, "now", "", "current time in RFC3339 format")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeIssueUsage(stdout)

			return exitSuccess
		}

		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		writeIssueUsage(stderr)

		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "pwp issue: unexpected positional argument")

		writeIssueUsage(stderr)

		return exitUsage
	}

	if policyPath == "" {
		fmt.Fprintln(stderr, "pwp issue: --policy is required")

		writeIssueUsage(stderr)

		return exitUsage
	}

	if subject == "" {
		fmt.Fprintln(stderr, "pwp issue: --subject is required")

		writeIssueUsage(stderr)

		return exitUsage
	}

	if outputPath == "" {
		fmt.Fprintln(stderr, "pwp issue: --out must not be empty")

		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	if storePath == "" {
		storePath = cfg.Issue.Store
	}

	if storePath == "" {
		fmt.Fprintln(stderr, "pwp issue: --store is required when issue.store is empty")

		writeIssueUsage(stderr)

		return exitUsage
	}

	prepared, err := app.Prepare(ctx, cfg, app.PrepareOptions{})
	if err != nil {
		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	source := random.DefaultSource()

	_, err = app.EvaluateStrength(ctx, source, prepared)
	if err != nil {
		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	historyTTL, err := parseIssueDuration(cfg.Issue.History.Ttl)
	if err != nil {
		fmt.Fprintf(stderr, "pwp issue: parse history ttl: %v\n", err)

		return exitUsage
	}

	rotateAfter, err := parseIssueDuration(cfg.Issue.RotateAfter)
	if err != nil {
		fmt.Fprintf(stderr, "pwp issue: parse rotate after: %v\n", err)

		return exitUsage
	}

	now := time.Now().UTC()

	if nowValue != "" {
		parsedNow, err := time.Parse(time.RFC3339, nowValue)
		if err != nil {
			fmt.Fprintf(stderr, "pwp issue: invalid --now value %q: %v\n", nowValue, err)

			return exitUsage
		}

		now = parsedNow.UTC()
	}

	policyVersion, err := calculateIssuePolicyVersion(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "pwp issue: calculate policy version: %v\n", err)

		return exitUsage
	}

	store, err := history.Open(storePath)
	if err != nil {
		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	metadataErr := store.SaveMetadata(
		history.Metadata{
			HistoryWindow: cfg.Issue.History.Window,
			HistoryTTL:    historyTTL,
		},
	)
	if metadataErr != nil {
		closeErr := store.Close()

		err := errors.Join(metadataErr, closeErr)

		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	result, issueErr := issue.Issue(
		ctx,
		source,
		store,
		prepared.Alphabet,
		prepared.Generate,
		issue.Options{
			Subject:       subject,
			HistoryWindow: cfg.Issue.History.Window,
			RotateAfter:   rotateAfter,
			Now:           now,
			PolicyName:    cfg.Policy.Name,
			PolicyVersion: policyVersion,
			HistoryTTL:    historyTTL,
		},
	)

	closeErr := store.Close()

	if issueErr != nil || closeErr != nil {
		if result.Password != nil {
			secret.Zero(result.Password)
		}

		err := errors.Join(issueErr, closeErr)

		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	defer secret.Zero(result.Password)

	data := make([]byte, len(result.Password)+1)

	copy(data, result.Password)

	data[len(data)-1] = '\n'

	defer secret.Zero(data)

	if outputPath == "-" {
		if err := writeIssuedPassword(stdout, data); err != nil {
			fmt.Fprintf(stderr, "pwp issue: write stdout: %v\n", err)

			return exitFailure
		}

		return exitSuccess
	}

	if err := atomicfile.Write(outputPath, data, issuedPasswordFileMode); err != nil {
		fmt.Fprintf(stderr, "pwp issue: %v\n", err)

		return exitUsage
	}

	return exitSuccess
}

func calculateIssuePolicyVersion(cfg policy.Config) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("encode normalized policy: %w", err)
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:]), nil
}

func parseIssueDuration(input string) (time.Duration, error) {
	if input == "" {
		return 0, fmt.Errorf("empty duration")
	}

	if len(input) < 2 {
		return 0, fmt.Errorf("invalid duration %q", input)
	}

	numberPart := input[:len(input)-1]
	suffix := input[len(input)-1]

	value, err := strconv.ParseUint(numberPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", input, err)
	}

	var unit time.Duration

	switch suffix {
	case 's':
		unit = time.Second

	case 'm':
		unit = time.Minute

	case 'h':
		unit = time.Hour

	case 'd':
		unit = 24 * time.Hour

	default:
		return 0, fmt.Errorf("invalid duration suffix %q", suffix)
	}

	maxValue := uint64(^uint64(0) >> 1)

	maxDurationValue := maxValue / uint64(unit)

	if value > maxDurationValue {
		return 0, fmt.Errorf("duration %q is too large", input)
	}

	return time.Duration(value) * unit, nil
}

func writeIssuedPassword(w io.Writer, data []byte) error {
	written, err := w.Write(data)
	if err != nil {
		return err
	}

	if written != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

func writeIssueUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp issue --policy <file> --subject <subject> [--store <dir>] [--out <path|->] [--now <RFC3339>]

Options:
  --policy <file>       Path to policy file
  --subject <subject>   Subject to issue password for
  --store <dir>         History store directory; overrides issue.store
  --out <path|->        Output file or - for stdout (default -)
  --now <RFC3339>       Current time; defaults to system time
  -h, --help            Show this help`,
	)
}
