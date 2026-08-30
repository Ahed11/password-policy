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

func TestPlanRotationEmptyStore(t *testing.T) {
	store := openRotateTestStore(t)

	plan, err := store.PlanRotation(rotateTestNow())

	require.NoError(t, err)

	assert.NotNil(t, plan.Items)
	assert.Empty(t, plan.Items)

	assert.NotNil(t, plan.Warnings)
	assert.Empty(t, plan.Warnings)
}

func TestPlanRotationFutureExpiration(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	record := rotateTestRecord("svc-01", 1, now.Add(-time.Hour), now.Add(time.Hour))

	require.NoError(t, store.Save(record))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)

	assert.Empty(t, plan.Items)
	assert.Empty(t, plan.Warnings)
}

func TestPlanRotationExpired(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	record := rotateTestRecord("svc-01", 1, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	require.NoError(t, store.Save(record))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)
	require.Len(t, plan.Items, 1)

	item := plan.Items[0]

	assert.Equal(t, "svc-01", item.Subject)

	assert.True(t, record.IssuedAt.Equal(item.IssuedAt))

	assert.True(t, record.ExpiresAt.Equal(item.ExpiresAt))

	assert.Equal(t, RotationReasonExpired, item.Reason)

	assert.Empty(t, plan.Warnings)
}

func TestPlanRotationAtExpirationBoundary(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	record := rotateTestRecord("svc-01", 1, now.Add(-24*time.Hour), now)

	require.NoError(t, store.Save(record))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)

	require.Len(t, plan.Items, 1)

	assert.Equal(t, "svc-01", plan.Items[0].Subject)
}

func TestPlanRotationZeroExpiresAt(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	record := rotateTestRecord("svc-01", 1, now.Add(-48*time.Hour), time.Time{})

	require.NoError(t, store.Save(record))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)

	assert.Empty(t, plan.Items)
	assert.Empty(t, plan.Warnings)
}

func TestPlanRotationUsesLatestRecord(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	oldRecord := rotateTestRecord("svc-01", 1, now.Add(-72*time.Hour), now.Add(-48*time.Hour))

	latestRecord := rotateTestRecord("svc-01", 2, now.Add(-time.Hour), now.Add(time.Hour))

	require.NoError(t, store.Save(oldRecord))

	require.NoError(t, store.Save(latestRecord))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)

	assert.Empty(t, plan.Items)
	assert.Empty(t, plan.Warnings)
}

func TestPlanRotationLatestExpiredRecord(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	oldRecord := rotateTestRecord("svc-01", 1, now.Add(-72*time.Hour), now.Add(24*time.Hour))

	latestRecord := rotateTestRecord("svc-01", 2, now.Add(-48*time.Hour), now.Add(-time.Hour))

	require.NoError(t, store.Save(oldRecord))

	require.NoError(t, store.Save(latestRecord))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)
	require.Len(t, plan.Items, 1)

	assert.Equal(t, "svc-01", plan.Items[0].Subject)

	assert.True(t, latestRecord.IssuedAt.Equal(plan.Items[0].IssuedAt))
}

func TestPlanRotationUsesKeyAsTieBreaker(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	issuedAt := now.Add(-24 * time.Hour)

	first := rotateTestRecord("svc-01", 1, issuedAt, now.Add(-time.Hour))

	second := rotateTestRecord("svc-01", 2, issuedAt, now.Add(time.Hour))

	require.NoError(t, store.Save(first))

	require.NoError(t, store.Save(second))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)

	assert.Empty(t, plan.Items)
}

func TestPlanRotationMultipleSubjectsDeterministicOrder(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	svcB := rotateTestRecord("svc-b", 1, now.Add(-48*time.Hour), now.Add(-2*time.Hour))

	svcC := rotateTestRecord("svc-c", 2, now.Add(-72*time.Hour), now.Add(-3*time.Hour))

	svcA := rotateTestRecord("svc-a", 3, now.Add(-36*time.Hour), now.Add(-2*time.Hour))

	require.NoError(t, store.Save(svcB))
	require.NoError(t, store.Save(svcC))
	require.NoError(t, store.Save(svcA))

	firstPlan, err := store.PlanRotation(now)
	require.NoError(t, err)

	secondPlan, err := store.PlanRotation(now)
	require.NoError(t, err)

	assert.Equal(t, firstPlan, secondPlan)

	require.Len(t, firstPlan.Items, 3)

	assert.Equal(t, "svc-c", firstPlan.Items[0].Subject)

	assert.Equal(t, "svc-a", firstPlan.Items[1].Subject)

	assert.Equal(t, "svc-b", firstPlan.Items[2].Subject)
}

func TestPlanRotationClockMovedBackward(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	record := rotateTestRecord("svc-01", 1, now.Add(time.Hour), now.Add(2*time.Hour))

	require.NoError(t, store.Save(record))

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)

	assert.Empty(t, plan.Items)

	require.Len(t, plan.Warnings, 1)

	assert.Contains(t, plan.Warnings[0], "clock moved backwards")

	assert.Contains(t, plan.Warnings[0], "svc-01")
}

func TestPlanRotationWarningsAreDeterministic(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	require.NoError(t, store.Save(rotateTestRecord("svc-b", 1, now.Add(2*time.Hour), now.Add(3*time.Hour))))

	require.NoError(t, store.Save(rotateTestRecord("svc-a", 2, now.Add(time.Hour), now.Add(2*time.Hour))))

	first, err := store.PlanRotation(now)
	require.NoError(t, err)

	second, err := store.PlanRotation(now)
	require.NoError(t, err)

	assert.Equal(t, first.Warnings, second.Warnings)

	require.Len(t, first.Warnings, 2)

	assert.Contains(t, first.Warnings[0], "svc-a")

	assert.Contains(t, first.Warnings[1], "svc-b")
}

func TestPlanRotationDoesNotModifyStore(t *testing.T) {
	store := openRotateTestStore(t)

	now := rotateTestNow()

	first := rotateTestRecord("svc-01", 1, now.Add(-72*time.Hour), now.Add(-48*time.Hour))

	second := rotateTestRecord("svc-01", 2, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	require.NoError(t, store.Save(first))
	require.NoError(t, store.Save(second))

	before, err := store.List("svc-01")
	require.NoError(t, err)

	plan, err := store.PlanRotation(now)

	require.NoError(t, err)
	require.Len(t, plan.Items, 1)

	after, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Equal(t, before, after)

	assert.Len(t, after, 2)
}

func TestPlanRotationAfterReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	now := rotateTestNow()

	firstStore, err := Open(dir)
	require.NoError(t, err)

	record := rotateTestRecord("svc-01", 1, now.Add(-48*time.Hour), now.Add(-time.Hour))

	require.NoError(t, firstStore.Save(record))

	require.NoError(t, firstStore.Close())

	secondStore, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, secondStore.Close())
	})

	plan, err := secondStore.PlanRotation(now)

	require.NoError(t, err)
	require.Len(t, plan.Items, 1)

	assert.Equal(t, "svc-01", plan.Items[0].Subject)
}

func TestPlanRotationCorruptedRecord(t *testing.T) {
	store := openRotateTestStore(t)

	err := store.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)

			require.NotNil(t, bucket)

			var key [8]byte

			binary.BigEndian.PutUint64(key[:], 1)

			return bucket.Put(key[:], []byte("{invalid-json"))
		},
	)
	require.NoError(t, err)

	plan, err := store.PlanRotation(rotateTestNow())

	assert.Error(t, err)

	assert.ErrorContains(t, err, "decode history record key")

	assert.Equal(t, RotationPlan{}, plan)
}

func TestPlanRotationAfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	plan, err := store.PlanRotation(rotateTestNow())

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, RotationPlan{}, plan)
}

func TestPlanRotationNilStore(t *testing.T) {
	var store *Store

	plan, err := store.PlanRotation(rotateTestNow())

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, RotationPlan{}, plan)
}

func openRotateTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func rotateTestNow() time.Time {
	return time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
}

func rotateTestRecord(subject string, number byte, issuedAt time.Time, expiresAt time.Time) Record {
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

		ExpiresAt: func() time.Time {
			if expiresAt.IsZero() {
				return time.Time{}
			}

			return expiresAt.UTC()
		}(),

		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}
