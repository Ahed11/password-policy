package alphabet

import (
	"fmt"
	"sort"
	"unicode"
)

type classDefinition struct {
	name     string
	alphabet string
}

func buildClasses(classes []classDefinition, exclude string) ([]normalizedClass, []error) {
	diagnostics := []error{}

	normalizedClasses, normalizeClassErrors := normalizeClasses(classes, exclude)
	diagnostics = append(diagnostics, normalizeClassErrors...)

	validateClassErrors := validateClassIntersections(normalizedClasses)
	diagnostics = append(diagnostics, validateClassErrors...)

	return normalizedClasses, diagnostics
}

func normalizeClasses(classes []classDefinition, exclude string) ([]normalizedClass, []error) {
	normalizedClasses := make([]normalizedClass, 0, len(classes))
	diagnostics := []error{}

	for _, class := range classes {
		normalizedAlphabet, classErrors := normalizeClassAlphabet(class.name, class.alphabet, exclude)

		diagnostics = append(diagnostics, classErrors...)

		normalizedClasses = append(
			normalizedClasses,
			normalizedClass{
				name:     class.name,
				alphabet: normalizedAlphabet,
			},
		)
	}

	return normalizedClasses, diagnostics
}

func normalizeClassAlphabet(className string, rawAlphabet string, exclude string) ([]rune, []error) {
	var diagnostics []error

	rawRunes := []rune(rawAlphabet)

	// 1. проверка дубликатов в ИСХОДНОМ alphabet.
	seen := make(map[rune]struct{}, len(rawRunes))
	duplicateReported := make(map[rune]struct{})

	for _, r := range rawRunes {
		if _, exists := seen[r]; exists {
			if _, alreadyReported := duplicateReported[r]; !alreadyReported {
				diagnostics = append(diagnostics, fmt.Errorf("policy.classes[%q].alphabet: duplicate rune %q", className, r))

				duplicateReported[r] = struct{}{}
			}

			continue
		}

		seen[r] = struct{}{}
	}

	// 2. проверка запрещённых combining marks.
	markReported := make(map[rune]struct{})

	for _, r := range rawRunes {
		if !unicode.IsMark(r) {
			continue
		}

		if _, alreadyReported := markReported[r]; alreadyReported {
			continue
		}

		diagnostics = append(diagnostics, fmt.Errorf("policy.classes[%q].alphabet: combining rune %q is not allowed", className, r))

		markReported[r] = struct{}{}
	}

	// 3. потсройка множества исключаемых рун.
	excluded := make(map[rune]struct{})

	for _, r := range []rune(exclude) {
		excluded[r] = struct{}{}
	}

	// 4. постройка итогового алфавита без exclude и без повторов.
	normalized := make([]rune, 0, len(rawRunes))
	added := make(map[rune]struct{}, len(rawRunes))

	for _, r := range rawRunes {
		if _, isExcluded := excluded[r]; isExcluded {
			continue
		}

		if _, alreadyAdded := added[r]; alreadyAdded {
			continue
		}

		normalized = append(normalized, r)
		added[r] = struct{}{}
	}

	// 5. После exclude класс должен остаться непустым.
	if len(normalized) == 0 {
		diagnostics = append(diagnostics, fmt.Errorf("policy.classes[%q].alphabet: empty after exclude", className))
	}

	// 6. Порядок исходной строки не должен влиять на результат.
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i] < normalized[j]
	})

	return normalized, diagnostics
}
