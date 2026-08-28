package history

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordJSONRoundTrip(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 28, 12, 30, 0, 0, time.UTC)

	expiresAt := issuedAt.Add(24 * time.Hour)

	want := Record{
		Subject: "svc-01",
		Salt: []byte{
			0x01,
			0x02,
			0x03,
			0x04,
		},
		Hash: []byte{
			0xaa,
			0xbb,
			0xcc,
			0xdd,
		},
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		PolicyName:    "service-accounts",
		PolicyVersion: "version-123",
	}

	data, err := json.Marshal(want)
	require.NoError(t, err)

	var got Record

	err = json.Unmarshal(data, &got)
	require.NoError(t, err)

	assert.Equal(t, want.Subject, got.Subject)
	assert.Equal(t, want.Salt, got.Salt)
	assert.Equal(t, want.Hash, got.Hash)

	assert.True(t, want.IssuedAt.Equal(got.IssuedAt))

	assert.True(t, want.ExpiresAt.Equal(got.ExpiresAt))

	assert.Equal(t, want.PolicyName, got.PolicyName)

	assert.Equal(t, want.PolicyVersion, got.PolicyVersion)
}

func TestRecordJSONFieldNames(t *testing.T) {
	record := Record{
		Subject:       "svc-01",
		Salt:          []byte{1, 2, 3},
		Hash:          []byte{4, 5, 6},
		IssuedAt:      time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC),
		PolicyName:    "test-policy",
		PolicyVersion: "abc123",
	}

	data, err := json.Marshal(record)
	require.NoError(t, err)

	var fields map[string]json.RawMessage

	err = json.Unmarshal(data, &fields)
	require.NoError(t, err)

	expectedFields := []string{
		"subject",
		"salt",
		"hash",
		"issued_at",
		"expires_at",
		"policy_name",
		"policy_version",
	}

	assert.Len(t, fields, len(expectedFields))

	for _, field := range expectedFields {
		assert.Contains(t, fields, field)
	}
}

func TestRecordJSONEncodesSaltAndHashAsBase64(t *testing.T) {
	salt := []byte{
		0x01,
		0x02,
		0x03,
		0x04,
	}

	hash := []byte{
		0xaa,
		0xbb,
		0xcc,
		0xdd,
	}

	record := Record{
		Salt: salt,
		Hash: hash,
	}

	data, err := json.Marshal(record)
	require.NoError(t, err)

	var fields map[string]json.RawMessage

	err = json.Unmarshal(data, &fields)
	require.NoError(t, err)

	var encodedSalt string

	err = json.Unmarshal(fields["salt"], &encodedSalt)
	require.NoError(t, err)

	var encodedHash string

	err = json.Unmarshal(fields["hash"], &encodedHash)
	require.NoError(t, err)

	assert.Equal(t, base64.StdEncoding.EncodeToString(salt), encodedSalt)

	assert.Equal(t, base64.StdEncoding.EncodeToString(hash), encodedHash)
}

func TestRecordTimesRemainUTC(t *testing.T) {
	record := Record{
		IssuedAt:  time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(record)
	require.NoError(t, err)

	var got Record

	err = json.Unmarshal(data, &got)
	require.NoError(t, err)

	assert.Equal(t, time.UTC, got.IssuedAt.Location())
	assert.Equal(t, time.UTC, got.ExpiresAt.Location())
}

func TestRecordDoesNotContainPasswordField(t *testing.T) {
	recordType := reflect.TypeOf(Record{})

	_, exists := recordType.FieldByName("Password")

	assert.False(t, exists, "history Record must never contain a plaintext password field")

	data, err := json.Marshal(Record{Subject: "svc-01"})
	require.NoError(t, err)

	assert.NotContains(t, string(data), `"password"`)
}
