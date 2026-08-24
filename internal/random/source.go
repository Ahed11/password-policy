package random

import (
	cryptorand "crypto/rand"
)

type Source interface {
	Read(p []byte) (int, error)
}

func DefaultSource() Source {
	return cryptorand.Reader
}
