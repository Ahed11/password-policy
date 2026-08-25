package generate

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
)

func shuffleRunes(source random.Source, values []rune) error {
	err := random.Shuffle(source, len(values), func(i, j int) {
		values[i], values[j] = values[j], values[i]
	})
	if err != nil {
		return fmt.Errorf("shuffle password characters: %w", err)
	}

	return nil
}
