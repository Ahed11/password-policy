package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetKeyboardLayout(t *testing.T) {
	tests := []struct {
		name       string
		layoutName string
		want       keyboardLayout
		wantFound  bool
	}{
		{
			name:       "qwerty",
			layoutName: "qwerty",
			want:       qwertyLayout,
			wantFound:  true,
		},
		{
			name:       "jcuken",
			layoutName: "jcuken",
			want:       jcukenLayout,
			wantFound:  true,
		},
		{
			name:       "unknown_layout",
			layoutName: "unknown",
			want:       keyboardLayout{},
			wantFound:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, found := getKeyboardLayout(test.layoutName)

			assert.Equal(t, test.wantFound, found)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestBuiltInKeyboardLayoutsHaveSeparateRows(t *testing.T) {
	assert.Len(t, qwertyLayout.rows, 3)
	assert.Len(t, jcukenLayout.rows, 3)

	for _, row := range qwertyLayout.rows {
		assert.NotEmpty(t, row)
	}

	for _, row := range jcukenLayout.rows {
		assert.NotEmpty(t, row)
	}
}

func TestLoadKeyboardLayoutFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.txt")

	err := os.WriteFile(path, []byte("12345\nqwert\nasdf\n"), 0o600)
	require.NoError(t, err)

	layout, err := loadKeyboardLayoutFile(path)
	require.NoError(t, err)

	assert.Equal(t, path, layout.name)

	assert.Equal(
		t,
		[][]rune{
			[]rune("12345"),
			[]rune("qwert"),
			[]rune("asdf"),
		},
		layout.rows,
	)
}

func TestLoadKeyboardLayoutFileSkipsEmptyRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.txt")

	err := os.WriteFile(path, []byte("12345\n\nqwert\n"), 0o600)
	require.NoError(t, err)

	layout, err := loadKeyboardLayoutFile(path)
	require.NoError(t, err)

	assert.Equal(
		t,
		[][]rune{
			[]rune("12345"),
			[]rune("qwert"),
		},
		layout.rows,
	)
}

func TestLoadKeyboardLayoutFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")

	err := os.WriteFile(path, nil, 0o600)
	require.NoError(t, err)

	layout, err := loadKeyboardLayoutFile(path)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "contains no rows")
	assert.Equal(t, keyboardLayout{}, layout)
}

func TestLoadKeyboardLayoutFileInvalidUTF8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.txt")

	err := os.WriteFile(path, []byte{0xff, 0xfe, '\n'}, 0o600)
	require.NoError(t, err)

	layout, err := loadKeyboardLayoutFile(path)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "contains invalid UTF-8")
	assert.Equal(t, keyboardLayout{}, layout)
}

func TestLoadKeyboardLayoutFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")

	layout, err := loadKeyboardLayoutFile(path)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "open keyboard layout file")
	assert.Equal(t, keyboardLayout{}, layout)
}
