package history

import "fmt"

// Reused проверяет, совпадает ли кандидат с одной из защищённых записей истории.
func (s *Store) Reused(subject string, password []byte, window int) (bool, error) {
	if window < 0 {
		return false, fmt.Errorf("check password reuse: history window must not be negative, got %d", window)
	}

	if window == 0 {
		return false, nil
	}

	records, err := s.List(subject)
	if err != nil {
		return false, fmt.Errorf("check password reuse for subject %q: %w", subject, err)
	}

	if len(records) == 0 {
		return false, nil
	}

	start := len(records) - window

	if start < 0 {
		start = 0
	}

	for i := len(records) - 1; i >= start; i-- {
		if Matches(records[i], password) {
			return true, nil
		}
	}

	return false, nil
}
