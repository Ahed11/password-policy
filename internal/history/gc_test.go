package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCEmptyStore(t *testing.T) {
	store := openGCTestStore(t)

	result, err := store.GC(gcTestNow(), 24*time.Hour, 3)

	require.NoError(t, err)

	assert.Equal(t, GCResult{}, result)
}

func TestGCDeletesExpiredRecords(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	expired := gcTestRecord("svc-01", 1, now.Add(-48*time.Hour))

	fresh := gcTestRecord("svc-01", 2, now.Add(-12*time.Hour))

	require.NoError(t, store.Save(expired))

	require.NoError(t, store.Save(fresh))

	result, err := store.GC(now, 24*time.Hour, 0)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 1,
			Kept:    1,
		},
		result,
	)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, fresh, records[0])
}

func TestGCTTLZeroKeepsAllRecords(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	first := gcTestRecord("svc-01", 1, now.Add(-1000*time.Hour))

	second := gcTestRecord("svc-01", 2, now.Add(-500*time.Hour))

	require.NoError(t, store.Save(first))

	require.NoError(t, store.Save(second))

	result, err := store.GC(now, 0, 0)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 0,
			Kept:    2,
		},
		result,
	)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 2)
}

func TestGCPreservesMostRecentWindow(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	first := gcTestRecord("svc-01", 1, now.Add(-96*time.Hour))

	second := gcTestRecord("svc-01", 2, now.Add(-72*time.Hour))

	third := gcTestRecord("svc-01", 3, now.Add(-48*time.Hour))

	fourth := gcTestRecord("svc-01", 4, now.Add(-36*time.Hour))

	require.NoError(t, store.Save(first))
	require.NoError(t, store.Save(second))
	require.NoError(t, store.Save(third))
	require.NoError(t, store.Save(fourth))

	result, err := store.GC(now, 24*time.Hour, 2)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 2,
			Kept:    2,
		},
		result,
	)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, records, 2)

	assertRecordEqual(t, third, records[0])

	assertRecordEqual(t, fourth, records[1])
}

func TestGCWindowLargerThanHistoryKeepsEverything(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	first := gcTestRecord("svc-01", 1, now.Add(-100*time.Hour))

	second := gcTestRecord("svc-01", 2, now.Add(-90*time.Hour))

	require.NoError(t, store.Save(first))
	require.NoError(t, store.Save(second))

	result, err := store.GC(now, time.Hour, 10)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 0,
			Kept:    2,
		},
		result,
	)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 2)
}

func TestGCMultipleSubjectsProtectsWindowsIndependently(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	svc1Old := gcTestRecord("svc-01", 1, now.Add(-72*time.Hour))

	svc1Latest := gcTestRecord("svc-01", 2, now.Add(-48*time.Hour))

	svc2Old := gcTestRecord("svc-02", 3, now.Add(-96*time.Hour))

	svc2Latest := gcTestRecord("svc-02", 4, now.Add(-60*time.Hour))

	require.NoError(t, store.Save(svc1Old))
	require.NoError(t, store.Save(svc1Latest))
	require.NoError(t, store.Save(svc2Old))
	require.NoError(t, store.Save(svc2Latest))

	result, err := store.GC(now, 24*time.Hour, 1)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 2,
			Kept:    2,
		},
		result,
	)

	svc1Records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, svc1Records, 1)

	assertRecordEqual(t, svc1Latest, svc1Records[0])

	svc2Records, err := store.List("svc-02")
	require.NoError(t, err)
	require.Len(t, svc2Records, 1)

	assertRecordEqual(t, svc2Latest, svc2Records[0])
}

func TestGCDeletesAtTTLBoundary(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()
	ttl := 24 * time.Hour

	record := gcTestRecord("svc-01", 1, now.Add(-ttl))

	require.NoError(t, store.Save(record))

	result, err := store.GC(now, ttl, 0)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 1,
			Kept:    0,
		},
		result,
	)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Empty(t, records)
}

func TestGCDoesNotDeleteBeforeTTLBoundary(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()
	ttl := 24 * time.Hour

	record := gcTestRecord("svc-01", 1, now.Add(-ttl+time.Second))

	require.NoError(t, store.Save(record))

	result, err := store.GC(now, ttl, 0)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 0,
			Kept:    1,
		},
		result,
	)
}

func TestGCDoesNotDeleteWhenClockMovesBackward(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	record := gcTestRecord("svc-01", 1, now.Add(24*time.Hour))

	require.NoError(t, store.Save(record))

	result, err := store.GC(now, time.Hour, 0)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 0,
			Kept:    1,
		},
		result,
	)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, record, records[0])
}

func TestGCIgnoresRecordExpiresAt(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	record := gcTestRecord("svc-01", 1, now.Add(-2*time.Hour))

	record.ExpiresAt = now.Add(-time.Hour)

	require.NoError(t, store.Save(record))

	result, err := store.GC(now, 24*time.Hour, 0)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 0,
			Kept:    1,
		},
		result,
	)
}

func TestGCUsesKeyAsWindowTieBreaker(t *testing.T) {
	store := openGCTestStore(t)

	now := gcTestNow()

	issuedAt := now.Add(-48 * time.Hour)

	first := gcTestRecord("svc-01", 1, issuedAt)

	second := gcTestRecord("svc-01", 2, issuedAt)

	require.NoError(t, store.Save(first))

	require.NoError(t, store.Save(second))

	result, err := store.GC(now, 24*time.Hour, 1)

	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 1,
			Kept:    1,
		},
		result,
	)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, second, records[0])
}

func TestGCPersistsAfterReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	firstStore, err := Open(dir)
	require.NoError(t, err)

	now := gcTestNow()

	expired := gcTestRecord("svc-01", 1, now.Add(-48*time.Hour))

	fresh := gcTestRecord("svc-01", 2, now.Add(-time.Hour))

	require.NoError(t, firstStore.Save(expired))

	require.NoError(t, firstStore.Save(fresh))

	result, err := firstStore.GC(now, 24*time.Hour, 0)
	require.NoError(t, err)

	assert.Equal(
		t,
		GCResult{
			Deleted: 1,
			Kept:    1,
		},
		result,
	)

	require.NoError(t, firstStore.Close())

	secondStore, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, secondStore.Close())
	})

	records, err := secondStore.List("svc-01")

	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, fresh, records[0])
}

func TestGCNegativeTTL(t *testing.T) {
	store := openGCTestStore(t)

	result, err := store.GC(gcTestNow(), -time.Hour, 0)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "ttl must not be negative")

	assert.Equal(t, GCResult{}, result)
}

func TestGCNegativeWindow(t *testing.T) {
	store := openGCTestStore(t)

	result, err := store.GC(gcTestNow(), time.Hour, -1)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "history window must not be negative")

	assert.Equal(t, GCResult{}, result)
}

func TestGCAfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	result, err := store.GC(gcTestNow(), 24*time.Hour, 1)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, GCResult{}, result)
}

func TestGCNilStore(t *testing.T) {
	var store *Store

	result, err := store.GC(gcTestNow(), 24*time.Hour, 1)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, GCResult{}, result)
}

func openGCTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func gcTestNow() time.Time {
	return time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
}

func gcTestRecord(subject string, number byte, issuedAt time.Time) Record {
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

		IssuedAt: issuedAt.UTC(),

		ExpiresAt: issuedAt.UTC().Add(7 * 24 * time.Hour),

		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}
