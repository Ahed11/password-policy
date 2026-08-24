package dictionary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckAvailability(t *testing.T) {
	tests := []struct {
		name        string
		preparePath func(t *testing.T) string
		wantErr     bool
		errContains string
	}{
		{
			name: "empty_path",
			preparePath: func(t *testing.T) string {
				return ""
			},
			wantErr: false,
		},
		{
			name: "existing_regular_file",
			preparePath: func(t *testing.T) string {
				tempDir := t.TempDir()

				path := filepath.Join(tempDir, "dictionary.txt")

				if err := os.WriteFile(path, []byte("password\nadmin\nqwerty\n"), 0o600); err != nil {
					t.Fatalf("write dictionary file: %v", err)
				}

				return path
			},
			wantErr: false,
		},
		{
			name: "missing_file",
			preparePath: func(t *testing.T) string {
				tempDir := t.TempDir()

				return filepath.Join(tempDir, "missing-dictionary.txt")
			},
			wantErr:     true,
			errContains: "cannot be opened",
		},
		{
			name: "directory_instead_of_file",
			preparePath: func(t *testing.T) string {
				return t.TempDir()
			},
			wantErr:     true,
			errContains: "is not a regular file",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := test.preparePath(t)

			err := CheckAvailability(path)

			if test.wantErr {
				assert.Error(t, err)

				if test.errContains != "" {
					assert.ErrorContains(t, err, test.errContains)
				}

				return
			}

			assert.NoError(t, err)
		})
	}
}
