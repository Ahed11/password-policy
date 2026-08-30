package history

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadMetadata(t *testing.T) {
	store := openMetadataTestStore(t)

	want := Metadata{
		HistoryWindow: 5,
		HistoryTTL:    180 * 24 * time.Hour,
	}

	err := store.SaveMetadata(want)
	require.NoError(t, err)

	got, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, want, got)
}

func TestMetadataZeroValues(t *testing.T) {
	store := openMetadataTestStore(t)

	want := Metadata{
		HistoryWindow: 0,
		HistoryTTL:    0,
	}

	err := store.SaveMetadata(want)
	require.NoError(t, err)

	got, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, want, got)
}

func TestSaveMetadataOverwritesExistingMetadata(t *testing.T) {
	store := openMetadataTestStore(t)

	first := Metadata{
		HistoryWindow: 3,
		HistoryTTL:    30 * 24 * time.Hour,
	}

	second := Metadata{
		HistoryWindow: 10,
		HistoryTTL:    180 * 24 * time.Hour,
	}

	require.NoError(t, store.SaveMetadata(first))

	require.NoError(t, store.SaveMetadata(second))

	got, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, second, got)
}

func TestMetadataPersistsAfterReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	firstStore, err := Open(dir)
	require.NoError(t, err)

	want := Metadata{
		HistoryWindow: 7,
		HistoryTTL:    90 * 24 * time.Hour,
	}

	require.NoError(t, firstStore.SaveMetadata(want))

	require.NoError(t, firstStore.Close())

	secondStore, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, secondStore.Close())
	})

	got, err := secondStore.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, want, got)
}

func TestLoadMetadataNotFound(t *testing.T) {
	store := openMetadataTestStore(t)

	metadata, err := store.LoadMetadata()

	assert.Error(t, err)

	assert.True(t, errors.Is(err, ErrMetadataNotFound))

	assert.Equal(t, Metadata{}, metadata)
}

func TestLoadMetadataBucketWithoutConfig(t *testing.T) {
	store := openMetadataTestStore(t)

	err := store.db.Update(
		func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists(metadataBucket)

			return err
		},
	)
	require.NoError(t, err)

	metadata, err := store.LoadMetadata()

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrMetadataNotFound)

	assert.Equal(t, Metadata{}, metadata)
}

func TestSaveMetadataNegativeWindow(t *testing.T) {
	store := openMetadataTestStore(t)

	metadata := Metadata{
		HistoryWindow: -1,
		HistoryTTL:    24 * time.Hour,
	}

	err := store.SaveMetadata(metadata)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "history window must not be negative")

	_, loadErr := store.LoadMetadata()

	assert.ErrorIs(t, loadErr, ErrMetadataNotFound)
}

func TestSaveMetadataNegativeTTL(t *testing.T) {
	store := openMetadataTestStore(t)

	metadata := Metadata{
		HistoryWindow: 3,
		HistoryTTL:    -time.Hour,
	}

	err := store.SaveMetadata(metadata)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "history ttl must not be negative")

	_, loadErr := store.LoadMetadata()

	assert.ErrorIs(t, loadErr, ErrMetadataNotFound)
}

func TestInvalidMetadataDoesNotOverwriteExistingMetadata(t *testing.T) {
	store := openMetadataTestStore(t)

	want := Metadata{
		HistoryWindow: 5,
		HistoryTTL:    30 * 24 * time.Hour,
	}

	require.NoError(t, store.SaveMetadata(want))

	err := store.SaveMetadata(
		Metadata{
			HistoryWindow: -1,
			HistoryTTL:    30 * 24 * time.Hour,
		},
	)

	assert.Error(t, err)

	got, loadErr := store.LoadMetadata()
	require.NoError(t, loadErr)

	assert.Equal(t, want, got)
}

func TestLoadMetadataCorruptedJSON(t *testing.T) {
	store := openMetadataTestStore(t)

	putRawMetadata(t, store, []byte("{invalid-json"))

	metadata, err := store.LoadMetadata()

	assert.Error(t, err)

	assert.ErrorContains(t, err, "decode history metadata")

	assert.Equal(t, Metadata{}, metadata)
}

func TestLoadMetadataInvalidStoredWindow(t *testing.T) {
	store := openMetadataTestStore(t)

	putRawMetadata(t, store, []byte(`{"history_window":-1,"history_ttl_ns":0}`))

	metadata, err := store.LoadMetadata()

	assert.Error(t, err)

	assert.ErrorContains(t, err, "invalid history metadata")

	assert.ErrorContains(t, err, "history window must not be negative")

	assert.Equal(t, Metadata{}, metadata)
}

func TestLoadMetadataInvalidStoredTTL(t *testing.T) {
	store := openMetadataTestStore(t)

	putRawMetadata(t, store, []byte(`{"history_window":5,"history_ttl_ns":-1}`))

	metadata, err := store.LoadMetadata()

	assert.Error(t, err)

	assert.ErrorContains(t, err, "invalid history metadata")

	assert.ErrorContains(t, err, "history ttl must not be negative")

	assert.Equal(t, Metadata{}, metadata)
}

func TestSaveMetadataDoesNotModifyRecords(t *testing.T) {
	store := openMetadataTestStore(t)

	record := saveTestRecord("svc-01", 1)

	require.NoError(t, store.Save(record))

	before, err := store.List("svc-01")
	require.NoError(t, err)

	require.NoError(
		t,
		store.SaveMetadata(
			Metadata{
				HistoryWindow: 5,
				HistoryTTL:    30 * 24 * time.Hour,
			},
		),
	)

	after, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Equal(t, before, after)
}

func TestMetadataDoesNotDisappearWhenRecordsChange(t *testing.T) {
	store := openMetadataTestStore(t)

	want := Metadata{
		HistoryWindow: 5,
		HistoryTTL:    30 * 24 * time.Hour,
	}

	require.NoError(t, store.SaveMetadata(want))

	require.NoError(t, store.Save(saveTestRecord("svc-01", 1)))

	got, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, want, got)
}

func TestSaveMetadataAfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	err = store.SaveMetadata(
		Metadata{
			HistoryWindow: 5,
			HistoryTTL:    24 * time.Hour,
		},
	)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")
}

func TestLoadMetadataAfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	metadata, err := store.LoadMetadata()

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, Metadata{}, metadata)
}

func TestSaveMetadataNilStore(t *testing.T) {
	var store *Store

	err := store.SaveMetadata(
		Metadata{
			HistoryWindow: 5,
			HistoryTTL:    24 * time.Hour,
		},
	)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")
}

func TestLoadMetadataNilStore(t *testing.T) {
	var store *Store

	metadata, err := store.LoadMetadata()

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, Metadata{}, metadata)
}

func openMetadataTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func putRawMetadata(t *testing.T, store *Store, data []byte) {
	t.Helper()

	err := store.db.Update(
		func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(metadataBucket)
			if err != nil {
				return err
			}

			return bucket.Put(metadataConfigKey, data)
		},
	)

	require.NoError(t, err)
}
