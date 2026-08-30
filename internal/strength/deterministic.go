package strength

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/random"
)

type deterministicEntropySource struct {
	counter uint64
	block   [sha256.Size]byte
	offset  int
}

func newDeterministicEntropySource() random.Source {
	return &deterministicEntropySource{
		offset: sha256.Size,
	}
}

// Read заполняет p воспроизводимой последовательностью байтов для внутренней оценки энтропии.
func (source *deterministicEntropySource) Read(p []byte) (int, error) {
	written := 0

	for written < len(p) {
		if source.offset == sha256.Size {
			var counterBytes [8]byte

			binary.BigEndian.PutUint64(counterBytes[:], source.counter)

			source.block = sha256.Sum256(counterBytes[:])
			source.counter++
			source.offset = 0
		}

		n := copy(p[written:], source.block[source.offset:])

		written += n
		source.offset += n
	}

	return written, nil
}

// EstimateEntropyDeterministic вычисляет воспроизводимую нижнюю границу энтропии политики.
// Предсказуемый источник используется только для внутренней оценки стойкости и не предназначен для генерации паролей.
func EstimateEntropyDeterministic(
	buildResult alphabet.BuildResult,
	options generate.Options,
) (Estimate, error) {
	return EstimateEntropy(
		newDeterministicEntropySource(),
		buildResult,
		options,
	)
}
