package generate

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
)

func fillToLength(source random.Source, selected []rune, used map[rune]struct{}, unionAlphabet []rune, targetLength int, repeatTotal bool) ([]rune, error) {
	remaining := targetLength - len(selected)

	if remaining < 0 {
		return nil, fmt.Errorf("selected character count %d exceeds target length %d", len(selected), targetLength)
	}

	result := append([]rune(nil), selected...)

	if remaining == 0 {
		return result, nil
	}

	if len(unionAlphabet) == 0 {
		return nil, fmt.Errorf("cannot fill password to length %d: union alphabet is empty", targetLength)
	}

	if !repeatTotal {
		for i := 0; i < remaining; i++ {
			index, err := random.Range(source, len(unionAlphabet))
			if err != nil {
				return nil, fmt.Errorf("choose fill character %d of %d: %w", i+1, remaining, err)
			}

			result = append(result, unionAlphabet[index])
		}

		return result, nil
	}

	available := make([]rune, 0, len(unionAlphabet))

	for _, r := range unionAlphabet {
		if _, alreadyUsed := used[r]; alreadyUsed {
			continue
		}

		available = append(available, r)
	}

	if len(available) < remaining {
		return nil, fmt.Errorf("not enough unused characters to fill password: need %d, available %d", remaining, len(available))
	}

	for i := 0; i < remaining; i++ {
		index, err := random.Range(source, len(available))
		if err != nil {
			return nil, fmt.Errorf("choose unique fill character %d of %d: %w", i+1, remaining, err)
		}

		chosen := available[index]

		result = append(result, chosen)
		used[chosen] = struct{}{}

		lastIndex := len(available) - 1
		available[index] = available[lastIndex]
		available = available[:lastIndex]
	}

	return result, nil
}
