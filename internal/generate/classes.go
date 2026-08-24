package generate

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/random"
)

type classRequirement struct {
	name     string
	alphabet []rune
	min      int
}

func pickClassMinimums(source random.Source, classes []classRequirement, repeatTotal bool) ([]rune, map[rune]struct{}, error) {
	totalMinimum := 0

	for _, class := range classes {
		totalMinimum += class.min
	}

	selected := make([]rune, 0, totalMinimum)
	used := make(map[rune]struct{}, totalMinimum)

	for _, class := range classes {
		if class.min == 0 {
			continue
		}

		if len(class.alphabet) == 0 {
			return nil, nil, fmt.Errorf("class %q has an empty alphabet", class.name)
		}

		if repeatTotal && class.min > len(class.alphabet) {
			return nil, nil, fmt.Errorf("class %q requires %d unique characters, alphabet size is %d", class.name, class.min, len(class.alphabet))
		}

		if !repeatTotal {
			for i := 0; i < class.min; i++ {
				index, err := random.Range(source, len(class.alphabet))
				if err != nil {
					return nil, nil, fmt.Errorf("choose minimum character for class %q: %w", class.name, err)
				}

				r := class.alphabet[index]

				selected = append(selected, r)
				used[r] = struct{}{}
			}

			continue
		}

		available := append([]rune(nil), class.alphabet...)

		for i := 0; i < class.min; i++ {
			index, err := random.Range(source, len(available))
			if err != nil {
				return nil, nil, fmt.Errorf("choose unique minimum character for class %q: %w", class.name, err)
			}

			r := available[index]

			selected = append(selected, r)
			used[r] = struct{}{}

			lastIndex := len(available) - 1
			available[index] = available[lastIndex]
			available = available[:lastIndex]
		}
	}

	return selected, used, nil
}
