package generate

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
)

func chooseLength(source random.Source, min, max int) (int, error) {

	if min <= 0 {
		return 0, fmt.Errorf("length.min must be greater than 0")
	}

	if max < min {
		return 0, fmt.Errorf("length.max must be greater than or equal to length.min")
	}

	if min == max {
		return min, nil
	}

	count := max - min + 1

	offset, err := random.Range(source, count)

	if err != nil {
		return 0, fmt.Errorf("choose password length in [%d, %d]: %w", min, max, err)
	}

	length := min + offset

	return length, nil
}
