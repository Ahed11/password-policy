package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"os"

	"github.com/stretchr/testify/require"
)

func TestPolicyControlFiles(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		wantCode int
	}{
		{
			name:     "valid boundary",
			fileName: "valid_boundary.yaml",
			wantCode: exitSuccess,
		},
		{
			name:     "unknown field",
			fileName: "unknown_field.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "overlapping classes",
			fileName: "overlapping_classes.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "minimums exceed max",
			fileName: "minimums_exceed_max.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "empty class after exclude",
			fileName: "empty_class_after_exclude.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "repeat total union too small",
			fileName: "repeat_total_union_too_small.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "repeat total class too small",
			fileName: "repeat_total_class_too_small.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "attempts zero",
			fileName: "attempts_zero.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "invalid duration",
			fileName: "invalid_duration.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "history window too large",
			fileName: "history_window_too_large.yaml",
			wantCode: exitUsage,
		},
		{
			name:     "missing dictionary",
			fileName: "missing_dictionary.yaml",
			wantCode: exitUsage,
		},
	}

	for _, testCase := range tests {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			policyPath := filepath.Join("..", "..", "testdata", "control", testCase.fileName)

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{
					"policy",
					"validate",
					"--policy",
					policyPath,
				},
				bytes.NewReader(nil),
				&stdout,
				&stderr,
			)

			assert.Equal(t, testCase.wantCode, code)

			if testCase.wantCode == exitSuccess {
				assert.Empty(t, stderr.String())

				assert.Contains(t, stdout.String(), `"status": "policy is valid"`)

				return
			}

			assert.Empty(t, stdout.String())

			assert.Contains(t, stderr.String(), "pwp policy validate:")
		},
		)
	}
}

func TestPolicyControlGoldenErrors(t *testing.T) {
	tests := []struct {
		name       string
		policyFile string
		goldenFile string
	}{
		{
			name:       "unknown field",
			policyFile: "unknown_field.yaml",
			goldenFile: "unknown_field.txt",
		},
		{
			name:       "invalid duration",
			policyFile: "invalid_duration.yaml",
			goldenFile: "invalid_duration.txt",
		},
	}

	for _, testCase := range tests {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			policyPath := filepath.Join("..", "..", "testdata", "control", testCase.policyFile)

			goldenPath := filepath.Join("..", "..", "testdata", "golden", "errors", testCase.goldenFile)

			expected, err := os.ReadFile(goldenPath)
			require.NoError(t, err)

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{
					"policy",
					"validate",
					"--policy",
					policyPath,
				},
				bytes.NewReader(nil),
				&stdout,
				&stderr,
			)

			assert.Equal(t, exitUsage, code)

			assert.Empty(t, stdout.String())

			actual := bytes.ReplaceAll(stderr.Bytes(), []byte("\r\n"), []byte("\n"))

			expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))

			assert.Equal(t, string(expected), string(actual))
		},
		)
	}
}
