package history

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptNewPassword(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("new-password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))

	accepted, err := store.Accept("svc-01", password, 3, record)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, record, records[0])
}

func TestAcceptRejectsReusedPassword(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("same-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	first := acceptTestRecord("svc-01", password, 1, base)

	accepted, err := store.Accept("svc-01", password, 3, first)

	require.NoError(t, err)
	require.True(t, accepted)

	second := acceptTestRecord("svc-01", password, 50, base.Add(time.Hour))

	accepted, err = store.Accept("svc-01", password, 3, second)

	require.NoError(t, err)
	assert.False(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 1)
}

func TestAcceptWindowZeroAllowsReuse(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("same-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	first := acceptTestRecord("svc-01", password, 1, base)

	accepted, err := store.Accept("svc-01", password, 0, first)

	require.NoError(t, err)
	require.True(t, accepted)

	second := acceptTestRecord("svc-01", password, 50, base.Add(time.Hour))

	accepted, err = store.Accept("svc-01", password, 0, second)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 2)
}

func TestAcceptOnlyChecksMostRecentWindow(t *testing.T) {
	store := openAcceptTestStore(t)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	oldPassword := []byte("old-password")
	secondPassword := []byte("second-password")
	thirdPassword := []byte("third-password")

	defer secret.Zero(oldPassword)
	defer secret.Zero(secondPassword)
	defer secret.Zero(thirdPassword)

	require.NoError(t, store.Save(acceptTestRecord("svc-01", oldPassword, 1, base)))

	require.NoError(t, store.Save(acceptTestRecord("svc-01", secondPassword, 20, base.Add(time.Hour))))

	require.NoError(t, store.Save(acceptTestRecord("svc-01", thirdPassword, 40, base.Add(2*time.Hour))))

	newRecord := acceptTestRecord("svc-01", oldPassword, 60, base.Add(3*time.Hour))

	accepted, err := store.Accept("svc-01", oldPassword, 2, newRecord)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 4)
}

func TestAcceptRejectsPasswordInsideWindow(t *testing.T) {
	store := openAcceptTestStore(t)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	firstPassword := []byte("first-password")
	secondPassword := []byte("second-password")
	thirdPassword := []byte("third-password")

	defer secret.Zero(firstPassword)
	defer secret.Zero(secondPassword)
	defer secret.Zero(thirdPassword)

	require.NoError(t, store.Save(acceptTestRecord("svc-01", firstPassword, 1, base)))

	require.NoError(t, store.Save(acceptTestRecord("svc-01", secondPassword, 20, base.Add(time.Hour))))

	require.NoError(t, store.Save(acceptTestRecord("svc-01", thirdPassword, 40, base.Add(2*time.Hour))))

	record := acceptTestRecord("svc-01", secondPassword, 60, base.Add(3*time.Hour))

	accepted, err := store.Accept("svc-01", secondPassword, 2, record)

	require.NoError(t, err)
	assert.False(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 3)
}

func TestAcceptChecksOnlyRequestedSubject(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("shared-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.Save(acceptTestRecord("svc-02", password, 1, base)))

	record := acceptTestRecord("svc-01", password, 30, base.Add(time.Hour))

	accepted, err := store.Accept("svc-01", password, 5, record)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 1)
}

func TestAcceptSubjectMismatch(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-02", password, 1, time.Now().UTC())

	accepted, err := store.Accept("svc-01", password, 3, record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "does not match subject")

	assert.False(t, accepted)
}

func TestAcceptEmptySubject(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("", password, 1, time.Now().UTC())

	accepted, err := store.Accept("", password, 3, record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "subject must not be empty")

	assert.False(t, accepted)
}

func TestAcceptNegativeWindow(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Now().UTC())

	accepted, err := store.Accept("svc-01", password, -1, record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "history window must not be negative")

	assert.False(t, accepted)
}

func TestAcceptAfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Now().UTC())

	accepted, err := store.Accept("svc-01", password, 3, record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")

	assert.False(t, accepted)
}

func TestAcceptNilStore(t *testing.T) {
	var store *Store

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Now().UTC())

	accepted, err := store.Accept("svc-01", password, 3, record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")

	assert.False(t, accepted)
}

func TestAcceptConcurrentSamePassword(t *testing.T) {
	store := openAcceptTestStore(t)

	const goroutines = 16

	password := []byte("same-password")
	defer secret.Zero(password)

	issuedAt := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	start := make(chan struct{})
	results := make(chan bool, goroutines)
	errorsChannel := make(chan error, goroutines)

	var waitGroup sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		waitGroup.Add(1)

		go func(index int) {
			defer waitGroup.Done()

			<-start

			record := acceptTestRecord("svc-01", password, byte(index*16+1), issuedAt)

			accepted, err := store.Accept("svc-01", password, 5, record)

			if err != nil {
				errorsChannel <- err
				return
			}

			results <- accepted
		}(i)
	}

	close(start)

	waitGroup.Wait()

	close(results)
	close(errorsChannel)

	for err := range errorsChannel {
		assert.NoError(t, err)
	}

	acceptedCount := 0

	for accepted := range results {
		if accepted {
			acceptedCount++
		}
	}

	assert.Equal(t, 1, acceptedCount, "only one concurrent attempt may accept the same password")

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 1, "only one history record must be persisted")
}

func openAcceptTestStore(
	t *testing.T,
) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func acceptTestRecord(subject string, password []byte, saltSeed byte, issuedAt time.Time) Record {
	salt := make([]byte, SaltSize)

	for i := range salt {
		salt[i] = saltSeed + byte(i)
	}

	return Record{
		Subject:       subject,
		Salt:          salt,
		Hash:          HashPassword(salt, password),
		IssuedAt:      issuedAt.UTC(),
		ExpiresAt:     issuedAt.UTC().Add(24 * time.Hour),
		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}
