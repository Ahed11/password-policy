package history

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptNewPassword(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("new-password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC))

	metadata := acceptTestMetadata(3)

	accepted, err := store.Accept("svc-01", password, metadata, record)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, records, 1)

	assertRecordEqual(t, record, records[0])

	gotMetadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, metadata, gotMetadata)
}

func TestAcceptRejectsReusedPassword(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("same-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	metadata := acceptTestMetadata(3)

	first := acceptTestRecord("svc-01", password, 1, base)

	accepted, err := store.Accept("svc-01", password, metadata, first)

	require.NoError(t, err)
	require.True(t, accepted)

	second := acceptTestRecord("svc-01", password, 50, base.Add(time.Hour))

	accepted, err = store.Accept("svc-01", password, metadata, second)

	require.NoError(t, err)
	assert.False(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 1)

	gotMetadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, metadata, gotMetadata)
}

func TestAcceptRejectedPasswordDoesNotOverwriteMetadata(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("same-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)

	firstMetadata := Metadata{
		HistoryWindow: 3,
		HistoryTTL:    30 * 24 * time.Hour,
	}

	firstRecord := acceptTestRecord("svc-01", password, 1, base)

	accepted, err := store.Accept("svc-01", password, firstMetadata, firstRecord)

	require.NoError(t, err)
	require.True(t, accepted)

	secondMetadata := Metadata{
		HistoryWindow: 10,
		HistoryTTL:    180 * 24 * time.Hour,
	}

	secondRecord := acceptTestRecord("svc-01", password, 50, base.Add(time.Hour))

	accepted, err = store.Accept("svc-01", password, secondMetadata, secondRecord)

	require.NoError(t, err)
	assert.False(t, accepted)

	gotMetadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, firstMetadata, gotMetadata)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 1)
}

func TestAcceptWindowZeroAllowsReuse(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("same-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	metadata := acceptTestMetadata(0)

	first := acceptTestRecord("svc-01", password, 1, base)

	accepted, err := store.Accept("svc-01", password, metadata, first)

	require.NoError(t, err)
	require.True(t, accepted)

	second := acceptTestRecord("svc-01", password, 50, base.Add(time.Hour))

	accepted, err = store.Accept("svc-01", password, metadata, second)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 2)

	gotMetadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, metadata, gotMetadata)
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

	metadata := acceptTestMetadata(2)

	accepted, err := store.Accept("svc-01", oldPassword, metadata, newRecord)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 4)

	gotMetadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, metadata, gotMetadata)
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

	accepted, err := store.Accept("svc-01", secondPassword, acceptTestMetadata(2), record)

	require.NoError(t, err)
	assert.False(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 3)

	_, err = store.LoadMetadata()

	assert.ErrorIs(t, err, ErrMetadataNotFound)
}

func TestAcceptChecksOnlyRequestedSubject(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("shared-password")
	defer secret.Zero(password)

	base := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.Save(acceptTestRecord("svc-02", password, 1, base)))

	record := acceptTestRecord("svc-01", password, 30, base.Add(time.Hour))

	accepted, err := store.Accept("svc-01", password, acceptTestMetadata(5), record)

	require.NoError(t, err)
	assert.True(t, accepted)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 1)
}

func TestAcceptUpdatesMetadataOnSuccessfulIssue(t *testing.T) {
	store := openAcceptTestStore(t)

	firstPassword := []byte("first-password")
	secondPassword := []byte("second-password")

	defer secret.Zero(firstPassword)
	defer secret.Zero(secondPassword)

	base := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)

	firstMetadata := Metadata{
		HistoryWindow: 3,
		HistoryTTL:    30 * 24 * time.Hour,
	}

	firstAccepted, err := store.Accept("svc-01", firstPassword, firstMetadata, acceptTestRecord("svc-01", firstPassword, 1, base))

	require.NoError(t, err)
	require.True(t, firstAccepted)

	secondMetadata := Metadata{
		HistoryWindow: 7,
		HistoryTTL:    180 * 24 * time.Hour,
	}

	secondAccepted, err := store.Accept("svc-01", secondPassword, secondMetadata, acceptTestRecord("svc-01", secondPassword, 50, base.Add(time.Hour)))

	require.NoError(t, err)
	require.True(t, secondAccepted)

	gotMetadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, secondMetadata, gotMetadata)
}

func TestAcceptInvalidMetadataDoesNotSaveRecord(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC))

	accepted, err := store.Accept(
		"svc-01",
		password,
		Metadata{
			HistoryWindow: -1,
			HistoryTTL:    24 * time.Hour,
		},
		record,
	)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "history window must not be negative")

	assert.False(t, accepted)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)

	assert.Empty(t, records)

	_, metadataErr := store.LoadMetadata()

	assert.ErrorIs(t, metadataErr, ErrMetadataNotFound)
}

func TestAcceptNegativeTTLDoesNotSaveRecord(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Now().UTC())

	accepted, err := store.Accept(
		"svc-01",
		password,
		Metadata{
			HistoryWindow: 3,
			HistoryTTL:    -time.Hour,
		},
		record,
	)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "history ttl must not be negative")

	assert.False(t, accepted)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)

	assert.Empty(t, records)
}

func TestAcceptRollsBackRecordWhenMetadataWriteFails(t *testing.T) {
	store := openAcceptTestStore(t)

	err := store.db.Update(
		func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(metadataBucket)
			if err != nil {
				return err
			}

			_, err = bucket.CreateBucket(metadataConfigKey)

			return err
		},
	)
	require.NoError(t, err)

	password := []byte("new-password")
	defer secret.Zero(password)

	record := acceptTestRecord(
		"svc-01",
		password,
		1,
		time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC))

	accepted, err := store.Accept("svc-01", password, acceptTestMetadata(3), record)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store history metadata")

	assert.False(t, accepted)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)

	assert.Empty(t, records)
}

func TestAcceptSubjectMismatch(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-02", password, 1, time.Now().UTC())

	accepted, err := store.Accept("svc-01", password, acceptTestMetadata(3), record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "does not match subject")

	assert.False(t, accepted)
}

func TestAcceptEmptySubject(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("", password, 1, time.Now().UTC())

	accepted, err := store.Accept("", password, acceptTestMetadata(3), record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "subject must not be empty")

	assert.False(t, accepted)
}

func TestAcceptNegativeWindow(t *testing.T) {
	store := openAcceptTestStore(t)

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Now().UTC())

	metadata := acceptTestMetadata(3)
	metadata.HistoryWindow = -1

	accepted, err := store.Accept("svc-01", password, metadata, record)

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

	accepted, err := store.Accept("svc-01", password, acceptTestMetadata(3), record)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "store is not open")

	assert.False(t, accepted)
}

func TestAcceptNilStore(t *testing.T) {
	var store *Store

	password := []byte("password")
	defer secret.Zero(password)

	record := acceptTestRecord("svc-01", password, 1, time.Now().UTC())

	accepted, err := store.Accept("svc-01", password, acceptTestMetadata(3), record)

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

	metadata := acceptTestMetadata(5)

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

			accepted, err := store.Accept("svc-01", password, metadata, record)

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

	gotMetadata, err := store.LoadMetadata()
	require.NoError(t, err)

	assert.Equal(t, metadata, gotMetadata)
}

func openAcceptTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func acceptTestMetadata(window int) Metadata {
	return Metadata{
		HistoryWindow: window,
		HistoryTTL:    30 * 24 * time.Hour,
	}
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
