package dictionary

import "fmt"

// Match описывает найденное совпадение со словарным словом.
type Match struct {
	Offset int
	Length int
}

// Matcher хранит подготовленную структуру для поиска словарных совпадений.
type Matcher struct {
	tree            *trie
	caseInsensitive bool
	leet            bool
}

// Load загружает словарь из файла и создаёт структуру для последующего поиска.
func Load(path string, minLength int, caseInsensitive bool, leet bool) (*Matcher, error) {
	words, err := readWords(path, minLength, caseInsensitive)
	if err != nil {
		return nil, fmt.Errorf("load dictionary: %w", err)
	}

	return &Matcher{
		tree:            buildTrie(words),
		caseInsensitive: caseInsensitive,
		leet:            leet,
	}, nil
}

// Find ищет словарное совпадение в переданном значении.
func (m *Matcher) Find(password []byte) []Match {
	if m == nil {
		return nil
	}

	internalMatches := searchTrie(password, m.tree, m.caseInsensitive, m.leet)

	if len(internalMatches) == 0 {
		return nil
	}

	matches := make([]Match, 0, len(internalMatches))

	for _, match := range internalMatches {
		matches = append(matches, Match{
			Offset: match.offset,
			Length: match.length,
		})
	}

	return matches
}
