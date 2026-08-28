package history

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenCreatesStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)
	require.NotNil(t, store)
	require.NotNil(t, store.db)

	t.Cleanup(func() { require.NoError(t, store.Close()) })

	info, err := os.Stat(dir)
	require.NoError(t, err)

	assert.True(t, info.IsDir())

	databasePath := filepath.Join(dir, databaseFileName)

	databaseInfo, err := os.Stat(databasePath)
	require.NoError(t, err)

	assert.False(t, databaseInfo.IsDir())
}

func TestOpenCreatesRecordsBucket(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	err = store.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)

			require.NotNil(t, bucket, "records bucket must exist")

			return nil
		},
	)

	require.NoError(t, err)
}

func TestOpenReopensExistingStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	first, err := Open(dir)
	require.NoError(t, err)

	err = first.Close()
	require.NoError(t, err)

	second, err := Open(dir)
	require.NoError(t, err)
	require.NotNil(t, second)

	t.Cleanup(func() {
		require.NoError(t, second.Close())
	})

	err = second.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)

			require.NotNil(t, bucket)

			return nil
		},
	)

	require.NoError(t, err)
}

func TestOpenPreservesExistingData(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	first, err := Open(dir)
	require.NoError(t, err)

	key := []byte("test-key")
	value := []byte("test-value")

	err = first.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)

			require.NotNil(t, bucket)

			return bucket.Put(key, value)
		},
	)
	require.NoError(t, err)

	err = first.Close()
	require.NoError(t, err)

	second, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, second.Close())
	})

	err = second.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)

			require.NotNil(t, bucket)

			got := bucket.Get(key)

			assert.Equal(t, value, got)

			return nil
		},
	)

	require.NoError(t, err)
}

func TestOpenEmptyPath(t *testing.T) {
	store, err := Open("")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "path must not be empty")

	assert.Nil(t, store)
}

func TestOpenPathIsFile(t *testing.T) {
	root := t.TempDir()

	path := filepath.Join(root, "history")

	err := os.WriteFile(path, []byte("not a directory"), 0600)
	require.NoError(t, err)

	store, err := Open(path)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "create directory")

	assert.Nil(t, store)
}

func TestOpenDatabasePathIsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	err := os.MkdirAll(dir, 0700)
	require.NoError(t, err)

	databasePath := filepath.Join(dir, databaseFileName)

	err = os.Mkdir(databasePath, 0700)
	require.NoError(t, err)

	store, err := Open(dir)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "open history store database")

	assert.Nil(t, store)
}

func TestClose(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	require.NotNil(t, store.db)

	err = store.Close()

	require.NoError(t, err)
	assert.Nil(t, store.db)
}

func TestCloseTwice(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)

	err = store.Close()

	assert.NoError(t, err)
}

func TestCloseNilStore(t *testing.T) {
	var store *Store

	err := store.Close()

	assert.NoError(t, err)
}

func TestOpenDatabasePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not reliably represented on Windows")
	}

	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, databaseFileName))
	require.NoError(t, err)

	assert.Equal(t, os.FileMode(databaseFileMode), info.Mode().Perm())
}
