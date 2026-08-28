package history

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/Ahed11/password-policy/internal/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSalt(t *testing.T) {
	data := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}

	salt, err := GenerateSalt(bytes.NewReader(data))

	require.NoError(t, err)

	assert.Len(t, salt, SaltSize)
	assert.Equal(t, data, salt)
}

func TestGenerateSaltReadsPartialReads(t *testing.T) {
	data := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}

	source := &partialHistoryReader{
		data: data,
		max:  3,
	}

	salt, err := GenerateSalt(source)

	require.NoError(t, err)

	assert.Len(t, salt, SaltSize)
	assert.Equal(t, data, salt)
	assert.Greater(t, source.readCalls, 1)
}

func TestGenerateSaltSourceError(t *testing.T) {
	source := bytes.NewReader([]byte{0x01, 0x02, 0x03})

	salt, err := GenerateSalt(source)

	assert.Error(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

	assert.Nil(t, salt)

	assert.ErrorContains(t, err, "generate history salt")
}

func TestGenerateSaltEmptySource(t *testing.T) {
	salt, err := GenerateSalt(bytes.NewReader(nil))

	assert.Error(t, err)
	assert.ErrorIs(t, err, io.EOF)
	assert.Nil(t, salt)
}

func TestGenerateSaltNilSource(t *testing.T) {
	salt, err := GenerateSalt(nil)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "random source must not be nil")

	assert.Nil(t, salt)
}

func TestHashPassword(t *testing.T) {
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	password := []byte("correct-horse")

	expectedHasher := sha256.New()

	_, err := expectedHasher.Write(salt)
	require.NoError(t, err)

	_, err = expectedHasher.Write(password)
	require.NoError(t, err)

	expected := expectedHasher.Sum(nil)

	got := HashPassword(salt, password)

	assert.Equal(t, expected, got)
	assert.Len(t, got, sha256.Size)

	secret.Zero(password)
}

func TestHashPasswordIsDeterministic(t *testing.T) {
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	password := []byte("secret-password")

	first := HashPassword(salt, password)

	second := HashPassword(salt, password)

	assert.Equal(t, first, second)

	secret.Zero(password)
}

func TestHashPasswordDifferentSaltChangesHash(t *testing.T) {
	password := []byte("secret-password")

	first := HashPassword([]byte{0x01, 0x02, 0x03, 0x04}, password)

	second := HashPassword([]byte{0x05, 0x06, 0x07, 0x08}, password)

	assert.NotEqual(t, first, second)

	secret.Zero(password)
}

func TestHashPasswordDifferentPasswordChangesHash(t *testing.T) {
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	firstPassword := []byte("password-one")
	secondPassword := []byte("password-two")

	first := HashPassword(salt, firstPassword)

	second := HashPassword(salt, secondPassword)

	assert.NotEqual(t, first, second)

	secret.Zero(firstPassword)
	secret.Zero(secondPassword)
}

func TestMatches(t *testing.T) {
	salt := []byte{0x10, 0x11, 0x12, 0x13}

	password := []byte("correct-password")

	record := Record{
		Salt: salt,
		Hash: HashPassword(salt, password),
	}

	assert.True(t, Matches(record, password))

	secret.Zero(password)
}

func TestMatchesWrongPassword(t *testing.T) {
	salt := []byte{0x10, 0x11, 0x12, 0x13}

	correctPassword := []byte("correct-password")
	wrongPassword := []byte("wrong-password")

	record := Record{
		Salt: salt,
		Hash: HashPassword(salt, correctPassword),
	}

	assert.False(t, Matches(record, wrongPassword))

	secret.Zero(correctPassword)
	secret.Zero(wrongPassword)
}

func TestMatchesDifferentSalt(t *testing.T) {
	password := []byte("correct-password")

	record := Record{
		Salt: []byte{0x01, 0x02, 0x03, 0x04},
		Hash: HashPassword([]byte{0x05, 0x06, 0x07, 0x08}, password),
	}

	assert.False(t, Matches(record, password))

	secret.Zero(password)
}

func TestMatchesInvalidStoredHashLength(t *testing.T) {
	password := []byte("correct-password")

	record := Record{
		Salt: []byte{0x01, 0x02},
		Hash: []byte{0x01, 0x02},
	}

	assert.False(t, Matches(record, password))

	secret.Zero(password)
}

type partialHistoryReader struct {
	data      []byte
	offset    int
	max       int
	readCalls int
}

func (r *partialHistoryReader) Read(p []byte) (int, error) {
	r.readCalls++

	if r.offset >= len(r.data) {
		return 0, io.EOF
	}

	remaining := len(r.data) - r.offset

	n := len(p)

	if n > r.max {
		n = r.max
	}

	if n > remaining {
		n = remaining
	}

	copy(p[:n], r.data[r.offset:r.offset+n])

	r.offset += n

	return n, nil
}
