package history

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyEmptyStore(t *testing.T) {
	store := openVerifyTestStore(t)

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 0, result.Checked)
	assert.NotNil(t, result.Issues)
	assert.Empty(t, result.Issues)
}

func TestVerifyHealthyRecord(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)
	assert.Empty(t, result.Issues)
}

func TestVerifyMultipleHealthyRecords(t *testing.T) {
	store := openVerifyTestStore(t)

	now := verifyTestNow()

	require.NoError(t, store.Save(verifyTestRecord("svc-01", 1, now)))

	require.NoError(t, store.Save(verifyTestRecord("svc-02", 2, now.Add(time.Hour))))

	require.NoError(t, store.Save(verifyTestRecord("svc-03", 3, now.Add(2*time.Hour))))

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 3, result.Checked)
	assert.Empty(t, result.Issues)
}

func TestVerifyContinuesAfterCorruptedJSON(t *testing.T) {
	store := openVerifyTestStore(t)

	now := verifyTestNow()

	first := verifyTestRecord("svc-01", 1, now)

	second := verifyTestRecord("svc-02", 2, now.Add(time.Hour))

	third := verifyTestRecord("svc-03", 3, now.Add(2*time.Hour))

	require.NoError(t, store.Save(first))
	require.NoError(t, store.Save(second))
	require.NoError(t, store.Save(third))

	putVerifyRawRecord(t, store, verifyTestKey(2), []byte("{invalid-json"))

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 3, result.Checked)

	require.Len(t, result.Issues, 1)

	assert.Equal(t, "0000000000000002", result.Issues[0].Key)

	assert.Contains(t, result.Issues[0].Message, "invalid record JSON")
}

func TestVerifyInvalidKeyLength(t *testing.T) {
	store := openVerifyTestStore(t)

	data, err := json.Marshal(verifyTestRecord("svc-01", 1, verifyTestNow()))
	require.NoError(t, err)

	putVerifyRawRecord(t, store, []byte{1, 2, 3}, data)

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)

	require.Len(t, result.Issues, 1)

	assert.Equal(t, "010203", result.Issues[0].Key)

	assert.Contains(t, result.Issues[0].Message, "invalid record key length")
}

func TestVerifyNestedBucket(t *testing.T) {
	store := openVerifyTestStore(t)

	err := store.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			_, err := bucket.CreateBucket([]byte("nested"))

			return err
		},
	)
	require.NoError(t, err)

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "nested bucket")
}

func TestVerifyShortSalt(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.Salt = []byte{1, 2, 3}

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)

	require.Len(t, result.Issues, 1)

	assert.Equal(t, "svc-01", result.Issues[0].Subject)

	assert.Contains(t, result.Issues[0].Message, "salt is too short")
}

func TestVerifyInvalidHashLength(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.Hash = []byte{1, 2, 3}

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "invalid hash length")
}

func TestVerifyEmptySubject(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("", 1, verifyTestNow())

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "subject must not be empty")
}

func TestVerifyZeroIssuedAt(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.IssuedAt = time.Time{}
	record.ExpiresAt = time.Time{}

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "issued_at must not be zero")
}

func TestVerifyExpiresAtBeforeIssuedAt(t *testing.T) {
	store := openVerifyTestStore(t)

	now := verifyTestNow()

	record := verifyTestRecord("svc-01", 1, now)

	record.ExpiresAt = now.Add(-time.Hour)

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "expires_at must not be before issued_at")
}

func TestVerifyZeroExpiresAtIsValid(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.ExpiresAt = time.Time{}

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)
	assert.Empty(t, result.Issues)
}

func TestVerifyIssuedAtMustBeUTC(t *testing.T) {
	store := openVerifyTestStore(t)

	location := time.FixedZone("UTC+3", 3*60*60)

	issuedAt := time.Date(2026, time.August, 29, 12, 0, 0, 0, location)

	record := verifyTestRecord("svc-01", 1, issuedAt)

	record.IssuedAt = issuedAt

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "issued_at must be stored in UTC")
}

func TestVerifyExpiresAtMustBeUTC(t *testing.T) {
	store := openVerifyTestStore(t)

	location := time.FixedZone("UTC+3", 3*60*60)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.ExpiresAt = time.Date(2026, time.August, 30, 15, 0, 0, 0, location)

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "expires_at must be stored in UTC")
}

func TestVerifyEmptyPolicyName(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.PolicyName = ""

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "policy_name must not be empty")
}

func TestVerifyEmptyPolicyVersion(t *testing.T) {
	store := openVerifyTestStore(t)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.PolicyVersion = ""

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "policy_version must not be empty")
}

func TestVerifyReportsMultipleIssuesForOneRecord(t *testing.T) {
	store := openVerifyTestStore(t)

	record := Record{
		Subject:       "",
		Salt:          []byte{1},
		Hash:          []byte{2},
		IssuedAt:      time.Time{},
		ExpiresAt:     time.Time{},
		PolicyName:    "",
		PolicyVersion: "",
	}

	require.NoError(t, store.Save(record))

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)

	assert.Len(t, result.Issues, 6)

	messages := make([]string, 0, len(result.Issues))

	for _, issue := range result.Issues {
		messages = append(messages, issue.Message)
	}

	assert.Contains(t, messages, "subject must not be empty")

	assert.Contains(t, messages, "salt is too short: got 1 bytes, want at least 16")

	assert.Contains(t, messages, "invalid hash length: got 1 bytes, want 32")

	assert.Contains(t, messages, "issued_at must not be zero")

	assert.Contains(t, messages, "policy_name must not be empty")

	assert.Contains(t, messages, "policy_version must not be empty")
}

func TestVerifyControlCorruptedHistoryRecord(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "control", "corrupted_history_record.json")

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var record Record

	err = json.Unmarshal(data, &record)
	require.NoError(t, err)

	store := openVerifyTestStore(t)

	require.NoError(t, store.Save(record))

	result, err := store.Verify()
	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)

	require.Len(t, result.Issues, 5)

	messages := make([]string, 0, len(result.Issues))

	for _, issue := range result.Issues {
		assert.Equal(t, "svc-corrupt", issue.Subject)

		messages = append(messages, issue.Message)
	}

	assert.ElementsMatch(
		t,
		[]string{
			"salt is too short: got 3 bytes, want at least 16",
			"invalid hash length: got 3 bytes, want 32",
			"expires_at must not be before issued_at",
			"policy_name must not be empty",
			"policy_version must not be empty",
		},
		messages,
	)
}

func TestVerifyIssuesAreDeterministic(t *testing.T) {
	store := openVerifyTestStore(t)

	now := verifyTestNow()

	second := verifyTestRecord("svc-b", 2, now)
	second.Hash = []byte{1}

	first := verifyTestRecord("svc-a", 1, now)
	first.Salt = []byte{1}

	firstData, err := json.Marshal(first)
	require.NoError(t, err)

	secondData, err := json.Marshal(second)
	require.NoError(t, err)

	putVerifyRawRecord(t, store, verifyTestKey(2), secondData)

	putVerifyRawRecord(t, store, verifyTestKey(1), firstData)

	firstResult, err := store.Verify()
	require.NoError(t, err)

	secondResult, err := store.Verify()
	require.NoError(t, err)

	assert.Equal(t, firstResult, secondResult)

	require.Len(t, firstResult.Issues, 2)

	assert.Equal(t, "0000000000000001", firstResult.Issues[0].Key)

	assert.Equal(t, "0000000000000002", firstResult.Issues[1].Key)
}

func TestVerifyPersistsAfterReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	firstStore, err := Open(dir)
	require.NoError(t, err)

	record := verifyTestRecord("svc-01", 1, verifyTestNow())

	record.Hash = []byte{1, 2}

	require.NoError(t, firstStore.Save(record))

	require.NoError(t, firstStore.Close())

	secondStore, err := Open(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, secondStore.Close())
	})

	result, err := secondStore.Verify()

	require.NoError(t, err)

	assert.Equal(t, 1, result.Checked)

	require.Len(t, result.Issues, 1)

	assert.Contains(t, result.Issues[0].Message, "invalid hash length")
}

func TestVerifyDoesNotModifyStore(t *testing.T) {
	store := openVerifyTestStore(t)

	now := verifyTestNow()

	first := verifyTestRecord("svc-01", 1, now)

	second := verifyTestRecord("svc-01", 2, now.Add(time.Hour))

	require.NoError(t, store.Save(first))
	require.NoError(t, store.Save(second))

	before, err := store.List("svc-01")
	require.NoError(t, err)

	result, err := store.Verify()

	require.NoError(t, err)

	assert.Equal(t, 2, result.Checked)
	assert.Empty(t, result.Issues)

	after, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Equal(t, before, after)
}

func TestVerifyAfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := Open(dir)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	result, err := store.Verify()

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, VerifyResult{}, result)
}

func TestVerifyNilStore(t *testing.T) {
	var store *Store

	result, err := store.Verify()

	assert.Error(t, err)

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, VerifyResult{}, result)
}

func openVerifyTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func verifyTestNow() time.Time {
	return time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
}

func verifyTestRecord(subject string, number byte, issuedAt time.Time) Record {
	salt := make([]byte, SaltSize)

	for i := range salt {
		salt[i] = number + byte(i)
	}

	hash := make([]byte, sha256.Size)

	for i := range hash {
		hash[i] = number + byte(i)
	}

	issuedAt = issuedAt.UTC()

	return Record{
		Subject: subject,
		Salt:    salt,
		Hash:    hash,

		IssuedAt: issuedAt,

		ExpiresAt: issuedAt.Add(24 * time.Hour),

		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}

func verifyTestKey(sequence uint64) []byte {
	var key [8]byte

	binary.BigEndian.PutUint64(key[:], sequence)

	return key[:]
}

func putVerifyRawRecord(t *testing.T, store *Store, key []byte, value []byte) {
	t.Helper()

	err := store.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			require.NotNil(t, bucket)

			return bucket.Put(key, value)
		},
	)

	require.NoError(t, err)
}
