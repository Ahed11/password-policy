package rules

import "github.com/Ahed11/password-policy/internal/dictionary"

type dictionaryViolation struct {
	offset int
	length int
}

func checkDictionary(password []byte, matcher *dictionary.Matcher) []dictionaryViolation {
	if len(password) == 0 || matcher == nil {
		return nil
	}

	matches := matcher.Find(password)
	if len(matches) == 0 {
		return nil
	}

	violations := make([]dictionaryViolation, 0, len(matches))

	for _, match := range matches {
		violations = append(violations, dictionaryViolation{
			offset: match.Offset,
			length: match.Length,
		})
	}

	return violations
}