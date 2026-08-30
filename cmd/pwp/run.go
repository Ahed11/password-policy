package main

import (
	"context"
	"flag"
	"fmt"
	"io"
)

const (
	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
)

const currentVersion = "dev"

func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if ctx == nil {
		fmt.Fprintln(stderr, "pwp: context must not be nil")

		return exitUsage
	}

	if stdin == nil {
		fmt.Fprintln(stderr, "pwp: stdin must not be nil")

		return exitUsage
	}

	if stdout == nil {
		return exitUsage
	}

	if stderr == nil {
		return exitUsage
	}

	if err := ctx.Err(); err != nil {
		fmt.Fprintf(stderr, "pwp: %v\n", err)

		return exitUsage
	}

	flags := flag.NewFlagSet("pwp", flag.ContinueOnError)

	flags.SetOutput(io.Discard)

	var verbose bool
	var showVersion bool
	var showHelp bool

	flags.BoolVar(&verbose, "verbose", false, "enable detailed output")

	flags.BoolVar(&showVersion, "version", false, "show version information")

	flags.BoolVar(&showHelp, "h", false, "show help")

	flags.BoolVar(&showHelp, "help", false, "show help")

	if err := flags.Parse(args); err != nil {
		fmt.Fprintf(stderr, "pwp: %v\n", err)

		writeUsage(stderr)

		return exitUsage
	}

	if showHelp {
		writeUsage(stdout)

		return exitSuccess
	}

	if showVersion {
		fmt.Fprintf(stdout, "pwp %s\n", currentVersion)

		return exitSuccess
	}

	args = flags.Args()

	if len(args) == 0 {
		writeUsage(stderr)

		return exitUsage
	}

	command := args[0]
	commandArgs := args[1:]

	if verbose {
		fmt.Fprintf(stderr, "pwp: verbose: running command %q\n", command)
	}

	var code int

	switch command {
	case "help":
		writeUsage(stdout)

		code = exitSuccess

	case "version":
		code = runVersion(commandArgs, stdout, stderr)

	case "policy":
		code = runPolicy(ctx, commandArgs, stdout, stderr)

	case "gen":
		code = runGen(ctx, commandArgs, stdout, stderr)

	case "check":
		code = runCheck(ctx, commandArgs, stdin, stdout, stderr)

	case "explain":
		code = runExplain(ctx, commandArgs, stdin, stdout, stderr)

	case "audit":
		code = runAudit(ctx, commandArgs, stdin, stdout, stderr)

	case "entropy":
		code = runEntropy(ctx, commandArgs, stdout, stderr)

	case "issue":
		code = runIssue(ctx, commandArgs, stdout, stderr)

	case "history":
		code = runHistory(ctx, commandArgs, stdout, stderr)

	case "rotate":
		code = runRotate(ctx, commandArgs, stdout, stderr)

	case "gc":
		code = runGC(ctx, commandArgs, stdout, stderr)

	case "verify":
		code = runVerify(ctx, commandArgs, stdout, stderr)

	default:
		fmt.Fprintf(stderr, "pwp: unknown command %q\n", command)

		writeUsage(stderr)

		code = exitUsage
	}

	if verbose {
		fmt.Fprintf(stderr, "pwp: verbose: command %q finished with exit code %d\n", command, code)
	}

	return code
}

func runVersion(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: pwp version")

		return exitUsage
	}

	fmt.Fprintf(stdout, "pwp %s\n", currentVersion)

	return exitSuccess
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(
		w,
		`Usage:
  pwp [global options] <command> [options]

Commands:
  gen               Generate a password
  check             Check a password against the policy
  explain           Explain password policy violations
  audit             Audit passwords
  entropy           Show password entropy information
  policy validate   Validate a policy file
  issue             Issue a password for a subject
  history           Show password history
  rotate            Build a password rotation plan
  gc                Garbage-collect expired history
  verify            Verify history store integrity
  version           Show version information

Global options:
  -h, --help         Show this help
  --verbose          Enable detailed output
  --version          Show version information`,
	)
}
