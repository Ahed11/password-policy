package alphabet

import "sort"

// ClassDefinition описывает именованный класс символов до нормализации.
type ClassDefinition struct {
	Name     string
	Alphabet string
}

// Class описывает нормализованный класс символов.
type Class struct {
	Name     string
	Alphabet []rune
}

// BuildResult содержит нормализованные классы и их объединённый алфавит.
type BuildResult struct {
	Classes []Class
	Union   []rune
}

// Build проверяет и нормализует определения классов, применяет исключения и строит объединённый алфавит.
func Build(definitions []ClassDefinition, exclude string) (BuildResult, []error) {
	internalDefinitions := make([]classDefinition, 0, len(definitions))

	for _, definition := range definitions {
		internalDefinitions = append(
			internalDefinitions,
			classDefinition{
				name:     definition.Name,
				alphabet: definition.Alphabet,
			},
		)
	}

	normalizedClasses, diagnostics := buildClasses(internalDefinitions, exclude)

	result := BuildResult{
		Classes: make([]Class, 0, len(normalizedClasses)),
	}

	unionSet := make(map[rune]struct{})

	for _, normalized := range normalizedClasses {
		result.Classes = append(
			result.Classes,
			Class{
				Name:     normalized.name,
				Alphabet: normalized.alphabet,
			},
		)

		for _, r := range normalized.alphabet {
			unionSet[r] = struct{}{}
		}
	}

	result.Union = make([]rune, 0, len(unionSet))

	for r := range unionSet {
		result.Union = append(result.Union, r)
	}

	sort.Slice(result.Union, func(i, j int) bool {
		return result.Union[i] < result.Union[j]
	})

	return result, diagnostics
}
