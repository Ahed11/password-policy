package history

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/Ahed11/password-policy/internal/random"
)

// SaltSize задаёт размер случайной соли для записей истории в байтах.
const SaltSize = 16

// GenerateSalt создаёт случайную соль для новой записи истории.
func GenerateSalt(source random.Source) ([]byte, error) {
	if source == nil {
		return nil, fmt.Errorf("generate history salt: random source must not be nil")
	}

	salt := make([]byte, SaltSize)

	if _, err := io.ReadFull(source, salt); err != nil {
		return nil, fmt.Errorf("generate history salt: read random bytes: %w", err)
	}

	return salt, nil
}

// HashPassword вычисляет hash пароля с использованием переданной соли.
func HashPassword(salt []byte, password []byte) []byte {
	hasher := sha256.New()

	hasher.Write(salt)
	hasher.Write(password)

	return hasher.Sum(nil)
}

// Matches проверяет, соответствует ли пароль hash, сохранённому в записи истории.
func Matches(record Record, password []byte) bool {
	calculated := HashPassword(record.Salt, password)

	return subtle.ConstantTimeCompare(calculated, record.Hash) == 1
}
