package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "long help",
			args: []string{"--help"},
		},
		{
			name: "short help",
			args: []string{"-h"},
		},
		{
			name: "help command",
			args: []string{"help"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(context.Background(), tt.args, bytes.NewReader(nil), &stdout, &stderr)

			assert.Equal(t, exitSuccess, code)

			assert.Contains(t, stdout.String(), "Usage:")

			assert.Contains(t, stdout.String(), "pwp [global options] <command> [options]")

			assert.Contains(t, stdout.String(), "-h, --help")

			assert.Contains(t, stdout.String(), "--verbose")

			assert.Contains(t, stdout.String(), "--version")

			assert.Empty(t, stderr.String())
		},
		)
	}
}

func TestRunWithoutArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), nil, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "Usage:")

	assert.Contains(t, stderr.String(), "pwp [global options] <command> [options]")
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"unknown"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), `unknown command "unknown"`)

	assert.Contains(t, stderr.String(), "Usage:")
}

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"version"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "pwp "+currentVersion+"\n", stdout.String())

	assert.Empty(t, stderr.String())
}

func TestRunGlobalVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"--version"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "pwp "+currentVersion+"\n", stdout.String())

	assert.Empty(t, stderr.String())
}

func TestRunVersionWithArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"version", "extra"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "usage: pwp version")
}

func TestRunVerboseVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"--verbose", "version"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitSuccess, code)

	assert.Equal(t, "pwp "+currentVersion+"\n", stdout.String())

	assert.Contains(t, stderr.String(), `pwp: verbose: running command "version"`)

	assert.Contains(t, stderr.String(), `pwp: verbose: command "version" finished with exit code 0`)
}

func TestRunVerboseDoesNotPrintCommandArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	const sensitiveArgument = "must-not-appear"

	code := run(context.Background(), []string{"--verbose", "version", sensitiveArgument}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), `pwp: verbose: running command "version"`)

	assert.Contains(t, stderr.String(), `pwp: verbose: command "version" finished with exit code 2`)

	assert.NotContains(t, stderr.String(), sensitiveArgument)
}

func TestRunUnknownGlobalFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"--unknown-global-option"}, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "flag provided but not defined")

	assert.Contains(t, stderr.String(), "pwp [global options] <command> [options]")
}

func TestRunCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(ctx, nil, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), context.Canceled.Error())
}

func TestRunNilContext(t *testing.T) {
	var ctx context.Context

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(ctx, nil, bytes.NewReader(nil), &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "context must not be nil")
}

func TestRunNilStdin(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"version"}, nil, &stdout, &stderr)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())

	assert.Contains(t, stderr.String(), "stdin must not be nil")
}

func TestRunNilStdout(t *testing.T) {
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"version"}, bytes.NewReader(nil), nil, &stderr)

	assert.Equal(t, exitUsage, code)
}

func TestRunNilStderr(t *testing.T) {
	var stdout bytes.Buffer

	code := run(context.Background(), []string{"version"}, bytes.NewReader(nil), &stdout, nil)

	assert.Equal(t, exitUsage, code)

	assert.Empty(t, stdout.String())
}

func TestRunUsageContainsRequiredCommands(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"--help"}, bytes.NewReader(nil), &stdout, &stderr)

	require.Equal(t, exitSuccess, code)

	usage := stdout.String()

	requiredCommands := []string{
		"gen",
		"check",
		"explain",
		"audit",
		"entropy",
		"policy validate",
		"issue",
		"history",
		"rotate",
		"gc",
		"verify",
		"version",
	}

	for _, command := range requiredCommands {
		assert.Contains(t, usage, command)
	}

	assert.Empty(t, stderr.String())
}

func TestRunUsageContainsRequiredGlobalOptions(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"--help"}, bytes.NewReader(nil), &stdout, &stderr)

	require.Equal(t, exitSuccess, code)

	usage := stdout.String()

	requiredOptions := []string{
		"-h, --help",
		"--verbose",
		"--version",
	}

	for _, option := range requiredOptions {
		assert.Contains(t, usage, option)
	}

	assert.Empty(t, stderr.String())
}
