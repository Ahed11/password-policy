package history

import (
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveRecord(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	want := saveTestRecord("svc-01", 1)

	err = store.Save(want)
	require.NoError(t, err)

	var got Record
	var count int

	err = store.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			return bucket.ForEach(
				func(key, value []byte) error {
					count++

					return json.Unmarshal(value, &got)
				},
			)
		},
	)
	require.NoError(t, err)

	assert.Equal(t, 1, count)

	assertRecordEqual(t, want, got)
}

func TestSaveUsesSequentialKeys(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	err = store.Save(saveTestRecord("svc-01", 1))
	require.NoError(t, err)

	err = store.Save(saveTestRecord("svc-02", 2))
	require.NoError(t, err)

	var sequences []uint64

	err = store.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			return bucket.ForEach(
				func(key, value []byte) error {
					require.Len(t, key, 8)
					require.NotNil(t, value)

					sequences = append(sequences, binary.BigEndian.Uint64(key))

					return nil
				},
			)
		},
	)
	require.NoError(t, err)

	assert.Equal(t, []uint64{1, 2}, sequences)
}

func TestSaveMultipleRecords(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	first := saveTestRecord("svc-01", 1)

	second := saveTestRecord("svc-02", 2)

	require.NoError(t, store.Save(first))

	require.NoError(t, store.Save(second))

	var records []Record

	err = store.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			return bucket.ForEach(
				func(key, value []byte) error {
					var record Record

					if err := json.Unmarshal(value, &record); err != nil {
						return err
					}

					records = append(records, record)

					return nil
				},
			)
		},
	)
	require.NoError(t, err)

	require.Len(t, records, 2)

	assertRecordEqual(t, first, records[0])

	assertRecordEqual(t, second, records[1])
}

func TestSavePersistsAfterReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	firstStore, err := Open(dir)
	require.NoError(t, err)

	want := saveTestRecord("svc-01", 1)

	err = firstStore.Save(want)
	require.NoError(t, err)

	err = firstStore.Close()
	require.NoError(t, err)

	secondStore, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, secondStore.Close())
	})

	var got Record
	var found bool

	err = secondStore.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			return bucket.ForEach(
				func(key, value []byte) error {
					found = true

					return json.Unmarshal(value, &got)
				},
			)
		},
	)
	require.NoError(t, err)

	assert.True(t, found)

	assertRecordEqual(t, want, got)
}

func TestSaveContinuesSequenceAfterReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	firstStore, err := Open(dir)
	require.NoError(t, err)

	require.NoError(t, firstStore.Save(saveTestRecord("svc-01", 1)))

	require.NoError(t, firstStore.Close())

	secondStore, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, secondStore.Close())
	})

	require.NoError(t, secondStore.Save(saveTestRecord("svc-02", 2)))

	var sequences []uint64

	err = secondStore.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			return bucket.ForEach(
				func(key, value []byte) error {
					sequences = append(sequences, binary.BigEndian.Uint64(key))

					return nil
				},
			)
		},
	)
	require.NoError(t, err)

	assert.Equal(t, []uint64{1, 2}, sequences)
}

func TestSaveAfterClose(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)

	err = store.Save(saveTestRecord("svc-01", 1))

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")
}

func TestSaveNilStore(t *testing.T) {
	var store *Store

	err := store.Save(saveTestRecord("svc-01", 1))

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")
}

func saveTestRecord(subject string, number byte) Record {
	issuedAt := time.Date(2026, time.August, 28, 12, int(number), 0, 0, time.UTC)

	return Record{
		Subject: subject,
		Salt: []byte{
			number,
			number + 1,
			number + 2,
			number + 3,
		},
		Hash: []byte{
			number + 10,
			number + 11,
			number + 12,
			number + 13,
		},
		IssuedAt:      issuedAt,
		ExpiresAt:     issuedAt.Add(24 * time.Hour),
		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}

func assertRecordEqual(t *testing.T, want Record, got Record) {
	t.Helper()

	assert.Equal(t, want.Subject, got.Subject)

	assert.Equal(t, want.Salt, got.Salt)

	assert.Equal(t, want.Hash, got.Hash)

	assert.True(t, want.IssuedAt.Equal(got.IssuedAt))

	assert.True(t, want.ExpiresAt.Equal(got.ExpiresAt))

	assert.Equal(t, want.PolicyName, got.PolicyName)

	assert.Equal(t, want.PolicyVersion, got.PolicyVersion)
}
