package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReusedWindowZero(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	password := []byte("secret-password")
	defer secret.Zero(password)

	reused, err := store.Reused("svc-01", password, 0)

	require.NoError(t, err)
	assert.False(t, reused)
}

func TestReusedEmptyHistory(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	password := []byte("secret-password")
	defer secret.Zero(password)

	reused, err := store.Reused("svc-01", password, 3)

	require.NoError(t, err)
	assert.False(t, reused)
}

func TestReusedLatestPassword(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	oldPassword := []byte("old-password")
	latestPassword := []byte("latest-password")

	defer secret.Zero(oldPassword)
	defer secret.Zero(latestPassword)

	require.NoError(t, store.Save(reuseTestRecord("svc-01", oldPassword, 1, base)))

	require.NoError(t, store.Save(reuseTestRecord("svc-01", latestPassword, 2, base.Add(time.Hour))))

	reused, err := store.Reused("svc-01", latestPassword, 1)

	require.NoError(t, err)
	assert.True(t, reused)
}

func TestReusedPasswordWithinWindow(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	firstPassword := []byte("password-one")
	secondPassword := []byte("password-two")
	thirdPassword := []byte("password-three")

	defer secret.Zero(firstPassword)
	defer secret.Zero(secondPassword)
	defer secret.Zero(thirdPassword)

	require.NoError(t, store.Save(reuseTestRecord("svc-01", firstPassword, 1, base)))

	require.NoError(t, store.Save(reuseTestRecord("svc-01", secondPassword, 2, base.Add(time.Hour))))

	require.NoError(t, store.Save(reuseTestRecord("svc-01", thirdPassword, 3, base.Add(2*time.Hour))))

	reused, err := store.Reused("svc-01", secondPassword, 2)

	require.NoError(t, err)
	assert.True(t, reused)
}

func TestReusedPasswordOutsideWindow(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	firstPassword := []byte("password-one")
	secondPassword := []byte("password-two")
	thirdPassword := []byte("password-three")

	defer secret.Zero(firstPassword)
	defer secret.Zero(secondPassword)
	defer secret.Zero(thirdPassword)

	require.NoError(t, store.Save(reuseTestRecord("svc-01", firstPassword, 1, base)))

	require.NoError(t, store.Save(reuseTestRecord("svc-01", secondPassword, 2, base.Add(time.Hour))))

	require.NoError(t, store.Save(reuseTestRecord("svc-01", thirdPassword, 3, base.Add(2*time.Hour))))

	reused, err := store.Reused("svc-01", firstPassword, 2)

	require.NoError(t, err)
	assert.False(t, reused)
}

func TestReusedWindowLargerThanHistory(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	password := []byte("old-password")
	defer secret.Zero(password)

	record := reuseTestRecord(
		"svc-01",
		password,
		1,
		time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))

	require.NoError(t, store.Save(record))

	reused, err := store.Reused("svc-01", password, 10)

	require.NoError(t, err)
	assert.True(t, reused)
}

func TestReusedDifferentPassword(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	storedPassword := []byte("stored-password")
	newPassword := []byte("new-password")

	defer secret.Zero(storedPassword)
	defer secret.Zero(newPassword)

	require.NoError(t, store.Save(reuseTestRecord("svc-01", storedPassword, 1, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))))

	reused, err := store.Reused("svc-01", newPassword, 5)

	require.NoError(t, err)
	assert.False(t, reused)
}

func TestReusedSamePasswordWithDifferentSalt(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	password := []byte("same-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	first := reuseTestRecord("svc-01", password, 1, base)

	second := reuseTestRecord("svc-01", password, 100, base.Add(time.Hour))

	assert.NotEqual(t, first.Hash, second.Hash)

	require.NoError(t, store.Save(first))

	require.NoError(t, store.Save(second))

	reused, err := store.Reused("svc-01", password, 2)

	require.NoError(t, err)
	assert.True(t, reused)
}

func TestReusedOnlyChecksRequestedSubject(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	password := []byte("shared-password")
	defer secret.Zero(password)

	require.NoError(t, store.Save(reuseTestRecord("svc-02", password, 1, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))))

	reused, err := store.Reused("svc-01", password, 5)

	require.NoError(t, err)
	assert.False(t, reused)
}

func TestReusedNegativeWindow(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	reused, err := store.Reused("svc-01", []byte("password"), -1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "history window must not be negative")

	assert.False(t, reused)
}

func TestReusedAfterClose(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	require.NoError(t, store.Close())

	password := []byte("password")
	defer secret.Zero(password)

	reused, err := store.Reused("svc-01", password, 1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")

	assert.False(t, reused)
}

func TestReusedNilStore(t *testing.T) {
	var store *Store

	password := []byte("password")
	defer secret.Zero(password)

	reused, err := store.Reused("svc-01", password, 1)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")

	assert.False(t, reused)
}

func reuseTestRecord(subject string, password []byte, saltSeed byte, issuedAt time.Time) Record {
	salt := []byte{
		saltSeed,
		saltSeed + 1,
		saltSeed + 2,
		saltSeed + 3,
		saltSeed + 4,
		saltSeed + 5,
		saltSeed + 6,
		saltSeed + 7,
		saltSeed + 8,
		saltSeed + 9,
		saltSeed + 10,
		saltSeed + 11,
		saltSeed + 12,
		saltSeed + 13,
		saltSeed + 14,
		saltSeed + 15,
	}

	return Record{
		Subject:       subject,
		Salt:          salt,
		Hash:          HashPassword(salt, password),
		IssuedAt:      issuedAt,
		ExpiresAt:     issuedAt.Add(24 * time.Hour),
		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}
