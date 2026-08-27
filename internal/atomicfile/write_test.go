package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	data := []byte("hello\n")

	err := Write(path, data, 0600)

	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)

	assert.Equal(t, data, got)
}

func TestWriteReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	err := os.WriteFile(path, []byte("old data"), 0600)
	require.NoError(t, err)

	newData := []byte("new data\n")

	err = Write(path, newData, 0600)

	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)

	assert.Equal(t, newData, got)
}

func TestWriteEmptyData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	err := Write(path, []byte{}, 0600)

	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)

	assert.Empty(t, got)
}

func TestWriteSetsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not reliably represented on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	err := Write(path, []byte("data"), 0640)

	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)

	assert.Equal(t, os.FileMode(0640), info.Mode().Perm())
}

func TestWriteLeavesNoTemporaryFileAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	err := Write(path, []byte("data"), 0600)

	require.NoError(t, err)

	matches, err := filepath.Glob(filepath.Join(dir, ".report.json.tmp-*"))
	require.NoError(t, err)

	assert.Empty(t, matches)
}

func TestWriteEmptyPath(t *testing.T) {
	err := Write("", []byte("data"), 0600)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "path must not be empty")
}

func TestWriteMissingDirectory(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "missing", "report.json")

	err := Write(path, []byte("data"), 0600)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "create temporary file")

	_, statErr := os.Stat(path)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestWriteTargetIsDirectory(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "report.json")

	err := os.Mkdir(target, 0700)
	require.NoError(t, err)

	err = Write(target, []byte("data"), 0600)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "rename temporary file")

	info, statErr := os.Stat(target)
	require.NoError(t, statErr)

	assert.True(t, info.IsDir())

	matches, globErr := filepath.Glob(filepath.Join(dir, ".report.json.tmp-*"))
	require.NoError(t, globErr)

	assert.Empty(t, matches)
}

func TestWriteDoesNotModifyExistingFileWhenRenameFails(t *testing.T) {
	dir := t.TempDir()

	target := filepath.Join(dir, "report.json")

	err := os.Mkdir(target, 0700)
	require.NoError(t, err)

	err = Write(target, []byte("new data"), 0600)

	assert.Error(t, err)

	info, statErr := os.Stat(target)
	require.NoError(t, statErr)

	assert.True(t, info.IsDir())
}
