package history

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListEmptyStore(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	records, err := store.List("svc-01")

	require.NoError(t, err)

	assert.NotNil(t, records)
	assert.Empty(t, records)
}

func TestListOneRecord(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	want := saveTestRecord("svc-01", 1)

	require.NoError(t, store.Save(want))

	records, err := store.List("svc-01")

	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, want, records[0])
}

func TestListFiltersBySubject(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	first := saveTestRecord("svc-01", 1)

	other := saveTestRecord("svc-02", 2)

	second := saveTestRecord("svc-01", 3)

	require.NoError(t, store.Save(first))

	require.NoError(t, store.Save(other))

	require.NoError(t, store.Save(second))

	records, err := store.List("svc-01")

	require.NoError(t, err)
	require.Len(t, records, 2)

	assertRecordEqual(t, first, records[0])

	assertRecordEqual(t, second, records[1])

	for _, record := range records {
		assert.Equal(t, "svc-01", record.Subject)
	}
}

func TestListSortsByIssuedAt(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	latest := saveTestRecord("svc-01", 1)
	latest.IssuedAt = base.Add(30 * time.Minute)

	earliest := saveTestRecord("svc-01", 2)
	earliest.IssuedAt = base.Add(10 * time.Minute)

	middle := saveTestRecord("svc-01", 3)
	middle.IssuedAt = base.Add(20 * time.Minute)

	require.NoError(t, store.Save(latest))

	require.NoError(t, store.Save(earliest))

	require.NoError(t, store.Save(middle))

	records, err := store.List("svc-01")

	require.NoError(t, err)
	require.Len(t, records, 3)

	assertRecordEqual(t, earliest, records[0])

	assertRecordEqual(t, middle, records[1])

	assertRecordEqual(t, latest, records[2])
}

func TestListUsesKeyAsTieBreaker(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	issuedAt := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	first := saveTestRecord("svc-01", 1)
	first.IssuedAt = issuedAt

	second := saveTestRecord("svc-01", 2)
	second.IssuedAt = issuedAt

	third := saveTestRecord("svc-01", 3)
	third.IssuedAt = issuedAt

	require.NoError(t, store.Save(first))

	require.NoError(t, store.Save(second))

	require.NoError(t, store.Save(third))

	records, err := store.List("svc-01")

	require.NoError(t, err)
	require.Len(t, records, 3)

	assertRecordEqual(t, first, records[0])

	assertRecordEqual(t, second, records[1])

	assertRecordEqual(t, third, records[2])
}

func TestListPersistsAfterReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	firstStore, err := Open(dir)
	require.NoError(t, err)

	want := saveTestRecord("svc-01", 1)

	require.NoError(t, firstStore.Save(want))

	require.NoError(t, firstStore.Close())

	secondStore, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, secondStore.Close())
	})

	records, err := secondStore.List("svc-01")

	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, want, records[0])
}

func TestListMissingSubject(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	require.NoError(t, store.Save(saveTestRecord("svc-01", 1)))

	records, err := store.List("missing")

	require.NoError(t, err)

	assert.NotNil(t, records)
	assert.Empty(t, records)
}

func TestListAfterClose(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	require.NoError(t, store.Close())

	records, err := store.List("svc-01")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")

	assert.Nil(t, records)
}

func TestListNilStore(t *testing.T) {
	var store *Store

	records, err := store.List("svc-01")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")

	assert.Nil(t, records)
}

func TestListCorruptedRecord(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	err = store.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			var key [8]byte

			binary.BigEndian.PutUint64(key[:], 1)

			return bucket.Put(key[:], []byte("{invalid-json"))
		},
	)
	require.NoError(t, err)

	records, err := store.List("svc-01")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "decode history record key")

	assert.Nil(t, records)
}

func TestListInvalidKeyLength(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	err = store.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			return bucket.Put([]byte{1, 2, 3}, []byte(`{"subject":"svc-01"}`))
		},
	)
	require.NoError(t, err)

	records, err := store.List("svc-01")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "invalid key length")

	assert.Nil(t, records)
}
