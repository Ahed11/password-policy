package issue

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/history"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssue(t *testing.T) {
	store := openIssueTestStore(t)

	now := time.Date(2026, time.August, 28, 15, 30, 0, 0, time.FixedZone("UTC+3", 3*60*60))

	salt := issueTestSalt(1)

	result, err := Issue(
		context.Background(),
		bytes.NewReader(salt),
		store,
		issueTestBuildResult(),
		issueTestGenerateOptions(3),
		Options{
			Subject:       "svc-01",
			HistoryWindow: 3,
			RotateAfter:   24 * time.Hour,
			Now:           now,
			PolicyName:    "test-policy",
			PolicyVersion: "version-1",
		},
	)

	require.NoError(t, err)
	defer secret.Zero(result.Password)

	assert.Equal(t, []byte{'a'}, result.Password)
	assert.Equal(t, 1, result.Attempts)

	expectedIssuedAt := now.UTC()
	expectedExpiresAt := expectedIssuedAt.Add(24 * time.Hour)

	assert.Equal(t, "svc-01", result.Record.Subject)
	assert.Equal(t, salt, result.Record.Salt)

	assert.Equal(t, history.HashPassword(salt, []byte{'a'}), result.Record.Hash)

	assert.True(t, expectedIssuedAt.Equal(result.Record.IssuedAt))

	assert.True(t, expectedExpiresAt.Equal(result.Record.ExpiresAt))

	assert.Equal(t, time.UTC, result.Record.IssuedAt.Location())

	assert.Equal(t, time.UTC, result.Record.ExpiresAt.Location())

	assert.Equal(t, "test-policy", result.Record.PolicyName)

	assert.Equal(t, "version-1", result.Record.PolicyVersion)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.True(t, history.Matches(records[0], result.Password))
}

func TestIssueWithoutRotation(t *testing.T) {
	store := openIssueTestStore(t)

	result, err := Issue(
		context.Background(),
		bytes.NewReader(
			issueTestSalt(1),
		),
		store,
		issueTestBuildResult(),
		issueTestGenerateOptions(1),
		Options{
			Subject:       "svc-01",
			HistoryWindow: 0,
			RotateAfter:   0,
			Now:           time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC),
			PolicyName:    "test-policy",
			PolicyVersion: "version-1",
		},
	)

	require.NoError(t, err)
	defer secret.Zero(result.Password)

	assert.True(t, result.Record.ExpiresAt.IsZero())
}

func TestIssueRejectsReusedPassword(t *testing.T) {
	store := openIssueTestStore(t)

	password := []byte{'a'}

	require.NoError(t, store.Save(issueTestHistoryRecord("svc-01", password, 50, time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC))))

	sourceData := make([]byte, 0, history.SaltSize*3)

	sourceData = append(sourceData, issueTestSalt(1)...)

	sourceData = append(sourceData, issueTestSalt(30)...)

	sourceData = append(sourceData, issueTestSalt(60)...)

	result, err := Issue(context.Background(), bytes.NewReader(sourceData), store, issueTestBuildResult(), issueTestGenerateOptions(3), issueTestOptions(3))

	assert.Error(t, err)

	assert.ErrorIs(t, err, ErrHistoryExhausted)

	assert.ErrorContains(t, err, "exhausted 3 attempts")

	assert.Equal(t, Result{}, result)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)

	assert.Len(t, records, 1)
}

func TestIssueHistoryWindowZeroAllowsReuse(t *testing.T) {
	store := openIssueTestStore(t)

	password := []byte{'a'}

	require.NoError(t, store.Save(issueTestHistoryRecord("svc-01", password, 50, time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC))))

	options := issueTestOptions(0)

	result, err := Issue(context.Background(), bytes.NewReader(issueTestSalt(1)), store, issueTestBuildResult(), issueTestGenerateOptions(1), options)

	require.NoError(t, err)
	defer secret.Zero(result.Password)

	assert.Equal(t, password, result.Password)

	records, err := store.List("svc-01")
	require.NoError(t, err)

	assert.Len(t, records, 2)
}

func TestIssueUsesSharedAttemptsForRulesAndHistory(t *testing.T) {
	store := openIssueTestStore(t)

	require.NoError(t, store.Save(issueTestHistoryRecord("svc-01", []byte{'b'}, 50, time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC))))

	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	generateOptions := generate.Options{
		MinLength: 1,
		MaxLength: 1,
		Attempts:  2,
		ClassMinimums: map[string]int{
			"letters": 1,
		},
		Rules: rules.Options{
			ContextValues: []string{
				"a",
			},
			ContextMinLength: 1,
		},
	}

	sourceData := []byte{0, 128}

	sourceData = append(sourceData, issueTestSalt(1)...)

	source := bytes.NewReader(sourceData)

	result, err := Issue(context.Background(), source, store, buildResult, generateOptions, issueTestOptions(1))

	assert.Error(t, err)

	assert.ErrorIs(t, err, ErrHistoryExhausted)

	assert.ErrorContains(t, err, "exhausted 2 attempts")

	assert.Equal(t, Result{}, result)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)
	assert.Len(t, records, 1)
}

func TestIssueSucceedsAfterHistoryRejection(t *testing.T) {
	store := openIssueTestStore(t)

	require.NoError(t, store.Save(issueTestHistoryRecord("svc-01", []byte{'a'}, 50, time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC))))

	buildResult := alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a', 'b'},
			},
		},
		Union: []rune{'a', 'b'},
	}

	generateOptions := generate.Options{
		MinLength: 1,
		MaxLength: 1,
		Attempts:  2,
		ClassMinimums: map[string]int{
			"letters": 1,
		},
		Rules: rules.Options{},
	}

	rejectedSalt := issueTestSalt(10)
	acceptedSalt := issueTestSalt(40)

	sourceData := []byte{0}

	sourceData = append(sourceData, rejectedSalt...)

	sourceData = append(sourceData, 128)

	sourceData = append(sourceData, acceptedSalt...)

	result, err := Issue(context.Background(), bytes.NewReader(sourceData), store, buildResult, generateOptions, issueTestOptions(1))

	require.NoError(t, err)
	defer secret.Zero(result.Password)

	assert.Equal(t, []byte{'b'}, result.Password)

	assert.Equal(t, 2, result.Attempts)

	assert.Equal(t, acceptedSalt, result.Record.Salt)

	records, err := store.List("svc-01")
	require.NoError(t, err)
	assert.Len(t, records, 2)
}

func TestIssuePolicyTooStrictWithoutHistory(t *testing.T) {
	store := openIssueTestStore(t)

	generateOptions := issueTestGenerateOptions(2)

	generateOptions.Rules = rules.Options{
		ContextValues: []string{
			"a",
		},
		ContextMinLength: 1,
	}

	result, err := Issue(context.Background(), bytes.NewReader(nil), store, issueTestBuildResult(), generateOptions, issueTestOptions(0))

	assert.Error(t, err)

	assert.ErrorIs(t, err, generate.ErrPolicyTooStrict)

	assert.ErrorContains(t, err, "exhausted 2 attempts")

	assert.Equal(t, Result{}, result)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)
	assert.Empty(t, records)
}

func TestIssueSaltSourceError(t *testing.T) {
	store := openIssueTestStore(t)

	result, err := Issue(context.Background(), bytes.NewReader(nil), store, issueTestBuildResult(), issueTestGenerateOptions(1), issueTestOptions(0))

	assert.Error(t, err)
	assert.ErrorIs(t, err, io.EOF)

	assert.ErrorContains(t, err, "generate salt")

	assert.Equal(t, Result{}, result)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)
	assert.Empty(t, records)
}

func TestIssueCanceledContext(t *testing.T) {
	store := openIssueTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Issue(ctx, bytes.NewReader(nil), store, issueTestBuildResult(), issueTestGenerateOptions(1), issueTestOptions(0))

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	assert.Equal(t, Result{}, result)

	records, listErr := store.List("svc-01")
	require.NoError(t, listErr)
	assert.Empty(t, records)
}

func TestIssueSaveError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")

	store, err := history.Open(dir)
	require.NoError(t, err)

	require.NoError(t, store.Close())

	result, err := Issue(context.Background(), bytes.NewReader(issueTestSalt(1)), store, issueTestBuildResult(), issueTestGenerateOptions(1), issueTestOptions(0))

	assert.Error(t, err)

	assert.ErrorContains(t, err, "accept history record")

	assert.ErrorContains(t, err, "store is not open")

	assert.Equal(t, Result{}, result)
}

func TestIssueInvalidSubject(t *testing.T) {
	store := openIssueTestStore(t)

	options := issueTestOptions(0)
	options.Subject = ""

	result, err := Issue(context.Background(), bytes.NewReader(nil), store, issueTestBuildResult(), issueTestGenerateOptions(1), options)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "subject must not be empty")

	assert.Equal(t, Result{}, result)
}

func TestIssueNegativeHistoryWindow(t *testing.T) {
	store := openIssueTestStore(t)

	options := issueTestOptions(0)
	options.HistoryWindow = -1

	result, err := Issue(context.Background(), bytes.NewReader(nil), store, issueTestBuildResult(), issueTestGenerateOptions(1), options)

	assert.Error(t, err)

	assert.ErrorContains(t, err, "history window must not be negative")

	assert.Equal(t, Result{}, result)
}

func TestIssueNilStore(t *testing.T) {
	result, err := Issue(context.Background(), bytes.NewReader(nil), nil, issueTestBuildResult(), issueTestGenerateOptions(1), issueTestOptions(0))

	assert.Error(t, err)

	assert.ErrorContains(t, err, "history store must not be nil")

	assert.Equal(t, Result{}, result)
}

func openIssueTestStore(t *testing.T) *history.Store {
	t.Helper()

	store, err := history.Open(filepath.Join(t.TempDir(), "history"))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	return store
}

func issueTestBuildResult() alphabet.BuildResult {
	return alphabet.BuildResult{
		Classes: []alphabet.Class{
			{
				Name:     "letters",
				Alphabet: []rune{'a'},
			},
		},
		Union: []rune{'a'},
	}
}

func issueTestGenerateOptions(attempts int) generate.Options {
	return generate.Options{
		MinLength: 1,
		MaxLength: 1,
		Attempts:  attempts,
		ClassMinimums: map[string]int{
			"letters": 1,
		},
		Rules: rules.Options{},
	}
}

func issueTestOptions(window int) Options {
	return Options{
		Subject:       "svc-01",
		HistoryWindow: window,
		RotateAfter:   24 * time.Hour,
		Now:           time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC),
		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}

func issueTestSalt(seed byte) []byte {
	salt := make([]byte, history.SaltSize)

	for i := range salt {
		salt[i] = seed + byte(i)
	}

	return salt
}

func issueTestHistoryRecord(subject string, password []byte, saltSeed byte, issuedAt time.Time) history.Record {
	salt := issueTestSalt(saltSeed)

	return history.Record{
		Subject:       subject,
		Salt:          salt,
		Hash:          history.HashPassword(salt, password),
		IssuedAt:      issuedAt.UTC(),
		ExpiresAt:     issuedAt.UTC().Add(24 * time.Hour),
		PolicyName:    "test-policy",
		PolicyVersion: "version-1",
	}
}
