package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/history"
	"github.com/Ahed11/password-policy/internal/issue"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
)

const (
	exitSuccess = 0
	exitFailure = 1
)

type commandResult struct {
	Stdout string
	Stderr string
	Code   int
}

func main() {
	if err := runDemo(); err != nil {
		fmt.Fprintf(os.Stderr, "\ndemo FAILED: %v\n", err)

		os.Exit(1)
	}

	fmt.Println("\ndemo PASSED")
}

func runDemo() error {
	var pwpPath string

	flag.StringVar(&pwpPath, "pwp", defaultPWPPath(), "path to pwp binary")

	flag.Parse()

	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional argument")
	}

	root, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("run demo from repository root: %w", err)
	}

	pwpPath, err = filepath.Abs(pwpPath)
	if err != nil {
		return fmt.Errorf("resolve pwp binary path: %w", err)
	}

	if _, err := os.Stat(pwpPath); err != nil {
		return fmt.Errorf("pwp binary %q is not available: %w", pwpPath, err)
	}

	buildDir := filepath.Join(root, "build", "demo")

	if err := os.RemoveAll(buildDir); err != nil {
		return fmt.Errorf("clean demo build directory: %w", err)
	}

	if err := os.MkdirAll(buildDir, 0o700); err != nil {
		return fmt.Errorf("create demo build directory: %w", err)
	}

	fmt.Println("Password Policy demo")
	fmt.Println("====================")

	policyPath := filepath.Join("demo", "policy.yaml")

	if _, err := runPWPStep(root, pwpPath, "Validate policy", exitSuccess, nil, "policy", "validate", "--policy", policyPath); err != nil {
		return err
	}

	if _, err := runPWPStep(root, pwpPath, "Estimate entropy", exitSuccess, nil, "entropy", "--policy", policyPath); err != nil {
		return err
	}

	generatedPath := filepath.Join("build", "demo", "generated.txt")

	if _, err := runPWPStep(root, pwpPath, "Generate five passwords", exitSuccess, nil, "gen", "--policy", policyPath, "--count", "5", "--out", generatedPath); err != nil {
		return err
	}

	fmt.Println("generated passwords were written to build/demo/generated.txt and are not displayed")

	if err := checkGeneratedPasswords(root, pwpPath, policyPath, filepath.Join(root, generatedPath)); err != nil {
		return err
	}

	if _, err := runPWPStep(root, pwpPath, "Explain intentionally weak password", exitFailure, nil, "explain", "--policy", policyPath, "--password-file", filepath.Join("demo", "weak.txt")); err != nil {
		return err
	}

	auditJSONPath := filepath.Join("build", "demo", "audit.json")

	auditHTMLPath := filepath.Join("build", "demo", "audit.html")

	if _, err := runPWPStep(root, pwpPath, "Audit 200 demo passwords", exitFailure, nil, "audit", "--policy", policyPath, "--input", filepath.Join("demo", "passwords.jsonl"), "--report", auditJSONPath, "--report-html", auditHTMLPath); err != nil {
		return err
	}

	if err := compareGoldenReports(root, auditJSONPath, auditHTMLPath); err != nil {
		return err
	}

	fmt.Println("golden reports: MATCH")

	historyStore := filepath.Join("build", "demo", "history")

	issuedDir := filepath.Join(root, "build", "demo", "issued")

	if err := os.MkdirAll(issuedDir, 0o700); err != nil {
		return fmt.Errorf("create issued-password directory: %w", err)
	}

	issues := []struct {
		Subject string
		Now     string
	}{
		{
			Subject: "svc-01",
			Now:     "2026-08-01T00:00:00Z",
		},
		{
			Subject: "svc-02",
			Now:     "2026-10-01T00:00:00Z",
		},
		{
			Subject: "svc-03",
			Now:     "2026-08-15T00:00:00Z",
		},
	}

	for _, item := range issues {
		outputPath := filepath.Join("build", "demo", "issued", item.Subject+".txt")

		if _, err := runPWPStep(root, pwpPath, "Issue password for "+item.Subject, exitSuccess, nil, "issue", "--policy", policyPath, "--subject", item.Subject, "--store", historyStore, "--out", outputPath, "--now", item.Now); err != nil {
			return err
		}

		fmt.Printf("password for %s was written to %s and is not displayed\n", item.Subject, outputPath)
	}

	for _, item := range issues {
		if _, err := runPWPStep(root, pwpPath, "Show history for "+item.Subject, exitSuccess, nil, "history", "--subject", item.Subject, "--store", historyStore); err != nil {
			return err
		}
	}

	if err := demonstrateHistoryExhausted(buildDir); err != nil {
		return err
	}

	if _, err := runPWPStep(root, pwpPath, "Build rotation plan", exitFailure, nil, "rotate", "--policy", policyPath, "--store", historyStore, "--now", "2026-12-01T00:00:00Z"); err != nil {
		return err
	}

	if _, err := runPWPStep(root, pwpPath, "Garbage-collect history", exitSuccess, nil, "gc", "--store", historyStore, "--now", "2027-08-01T00:00:00Z"); err != nil {
		return err
	}

	if _, err := runPWPStep(root, pwpPath, "Verify history store", exitSuccess, nil, "verify", "--store", historyStore); err != nil {
		return err
	}

	return nil
}

func checkGeneratedPasswords(root string, pwpPath string, policyPath string, generatedPath string) error {
	fmt.Println()
	fmt.Println("== Self-check generated passwords ==")

	data, err := os.ReadFile(generatedPath)
	if err != nil {
		return fmt.Errorf("read generated passwords: %w", err)
	}
	defer secret.Zero(data)

	data = bytes.TrimSuffix(data, []byte{'\n'})

	passwords := bytes.Split(data, []byte{'\n'})

	if len(passwords) != 5 {
		return fmt.Errorf("generated password count: got %d, want 5", len(passwords))
	}

	for i, password := range passwords {
		if len(password) == 0 {
			return fmt.Errorf("generated password %d is empty", i+1)
		}

		result, err := runPWP(root, pwpPath, password, "check", "--policy", policyPath, "--password-file", "-")
		if err != nil {
			return fmt.Errorf("check generated password %d: %w", i+1, err)
		}

		if result.Code != exitSuccess {
			return fmt.Errorf("generated password %d failed self-check: exit=%d stdout=%q stderr=%q", i+1, result.Code, result.Stdout, result.Stderr)
		}

		fmt.Printf("generated password %d: PASS\n", i+1)
	}

	return nil
}

func compareGoldenReports(root string, actualJSON string, actualHTML string) error {
	pairs := []struct {
		Actual   string
		Expected string
	}{
		{
			Actual:   actualJSON,
			Expected: filepath.Join("demo", "expected", "audit.json"),
		},
		{
			Actual:   actualHTML,
			Expected: filepath.Join("demo", "expected", "audit.html"),
		},
	}

	for _, pair := range pairs {
		actual, err := os.ReadFile(filepath.Join(root, pair.Actual))
		if err != nil {
			return fmt.Errorf("read actual report %q: %w", pair.Actual, err)
		}

		expected, err := os.ReadFile(filepath.Join(root, pair.Expected))
		if err != nil {
			return fmt.Errorf("read expected report %q: %w", pair.Expected, err)
		}

		if !bytes.Equal(normalizeNewlines(actual), normalizeNewlines(expected)) {
			return fmt.Errorf("report %q does not match %q", pair.Actual, pair.Expected)
		}
	}

	return nil
}

func normalizeNewlines(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

func demonstrateHistoryExhausted(buildDir string) error {
	fmt.Println()
	fmt.Println("== Demonstrate history_exhausted ==")

	storePath := filepath.Join(buildDir, "history-exhausted")

	if err := os.RemoveAll(storePath); err != nil {
		return fmt.Errorf("clean history-exhausted store: %w", err)
	}

	store, err := history.Open(storePath)
	if err != nil {
		return fmt.Errorf("open history-exhausted store: %w", err)
	}

	password := []byte{'a'}
	defer secret.Zero(password)

	salt := make([]byte, history.SaltSize)

	for i := range salt {
		salt[i] = byte(i + 1)
	}

	issuedAt := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)

	record := history.Record{
		Subject:       "svc-history-exhausted",
		Salt:          salt,
		Hash:          history.HashPassword(salt, password),
		IssuedAt:      issuedAt,
		ExpiresAt:     issuedAt.Add(90 * 24 * time.Hour),
		PolicyName:    "demo-history-exhausted",
		PolicyVersion: "demo-version-1",
	}

	if err := store.Save(record); err != nil {
		_ = store.Close()

		return fmt.Errorf("seed history-exhausted store: %w", err)
	}

	buildResult, diagnostics := alphabet.Build(
		[]alphabet.ClassDefinition{
			{
				Name:     "letters",
				Alphabet: "a",
			},
		},
		"",
	)

	if len(diagnostics) != 0 {
		_ = store.Close()

		return fmt.Errorf("build history-exhausted alphabet: %v", diagnostics)
	}

	_, issueErr := issue.Issue(
		context.Background(),
		zeroSource{},
		store,
		buildResult,
		generate.Options{
			MinLength: 1,
			MaxLength: 1,
			Attempts:  3,
			ClassMinimums: map[string]int{
				"letters": 1,
			},
			Rules: rules.Options{},
		},
		issue.Options{
			Subject:       "svc-history-exhausted",
			HistoryWindow: 1,
			HistoryTTL:    180 * 24 * time.Hour,
			RotateAfter:   90 * 24 * time.Hour,
			Now: issuedAt.Add(
				time.Hour,
			),
			PolicyName:    "demo-history-exhausted",
			PolicyVersion: "demo-version-1",
		},
	)

	closeErr := store.Close()
	if closeErr != nil {
		return fmt.Errorf("close history-exhausted store: %w", closeErr)
	}

	if !errors.Is(issueErr, issue.ErrHistoryExhausted) {
		return fmt.Errorf("expected history_exhausted, got %v", issueErr)
	}

	fmt.Println("history_exhausted: PASS (existing password was never revealed)")

	return nil
}

func runPWPStep(root string, pwpPath string, name string, expectedCode int, stdin []byte, args ...string) (commandResult, error) {
	fmt.Println()
	fmt.Printf("== %s ==\n", name)
	fmt.Printf("$ pwp %s\n", renderArgs(args))

	result, err := runPWP(root, pwpPath, stdin, args...)
	if err != nil {
		return commandResult{}, err
	}

	if result.Stdout != "" {
		fmt.Print(result.Stdout)

		if !strings.HasSuffix(result.Stdout, "\n") {
			fmt.Println()
		}
	}

	if result.Stderr != "" {
		fmt.Fprint(os.Stderr, result.Stderr)

		if !strings.HasSuffix(result.Stderr, "\n") {
			fmt.Fprintln(os.Stderr)
		}
	}

	if result.Code != expectedCode {
		return result, fmt.Errorf("command returned exit code %d, want %d", result.Code, expectedCode)
	}

	fmt.Printf("exit code: %d\n", result.Code)

	return result, nil
}

func runPWP(root string, pwpPath string, stdin []byte, args ...string) (commandResult, error) {
	cmd := exec.Command(pwpPath, args...)

	cmd.Dir = root

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := commandResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Code:   exitSuccess,
	}

	if err == nil {
		return result, nil
	}

	var exitErr *exec.ExitError

	if errors.As(err, &exitErr) {
		result.Code = exitErr.ExitCode()

		return result, nil
	}

	return commandResult{}, fmt.Errorf("run pwp command: %w", err)
}

func renderArgs(args []string) string {
	rendered := make([]string, 0, len(args))

	for _, arg := range args {
		if strings.ContainsAny(arg, " \t") {
			rendered = append(rendered, fmt.Sprintf("%q", arg))

			continue
		}

		rendered = append(rendered, arg)
	}

	return strings.Join(rendered, " ")
}

func defaultPWPPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(".", "pwp.exe")
	}

	return filepath.Join(".", "pwp")
}

type zeroSource struct{}

func (zeroSource) Read(data []byte) (int, error) {
	for i := range data {
		data[i] = 0
	}

	return len(data), nil
}
