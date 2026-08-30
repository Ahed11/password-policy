package random

import (
	cryptorand "crypto/rand"
)

// Source определяет интерфейс источника случайных байтов.
type Source interface {
	Read(p []byte) (int, error)
}

// DefaultSource возвращает криптографически стойкий источник случайности для production-использования.
func DefaultSource() Source {
	return cryptorand.Reader
}
