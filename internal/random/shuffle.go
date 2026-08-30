package random

import "fmt"

// Shuffle перемешивает элементы с помощью алгоритма Fisher-Yates и переданного источника случайности.
func Shuffle(source Source, n int, swap func(i, j int)) error {
	if n < 0 {
		return fmt.Errorf("shuffle size must be greater than or equal to 0")
	}

	if n <= 1 {
		return nil
	}

	if source == nil {
		return fmt.Errorf("random source is nil")
	}

	if swap == nil {
		return fmt.Errorf("shuffle swap function is nil")
	}

	for i := n - 1; i > 0; i-- {
		j, err := Range(source, i+1)
		if err != nil {
			return fmt.Errorf("shuffle index for position %d: %w", i, err)
		}

		swap(i, j)
	}

	return nil
}
