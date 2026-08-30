package rules

import (
	"fmt"
	"unicode/utf8"

	"github.com/Ahed11/password-policy/internal/alphabet"
)

// LengthResult содержит результат проверки длины пароля.
type LengthResult struct {
	Count  int
	Min    int
	Max    int
	Passed bool
}

// ClassResult содержит результат проверки минимального количества символов отдельного класса.
type ClassResult struct {
	Name    string
	Count   int
	Minimum int
	Passed  bool
}

// EvaluationOptions задаёт параметры полной оценки пароля по политике.
type EvaluationOptions struct {
	MinLength     int
	MaxLength     int
	ClassMinimums map[string]int
	Rules         Options
}

// Evaluation содержит полный результат проверки пароля по длине, классам и правилам запретов.
type Evaluation struct {
	Passed     bool
	Length     LengthResult
	Classes    []ClassResult
	Violations []Violation
}

// Evaluate выполняет полную проверку пароля по заданным параметрам политики.
func Evaluate(password []byte, buildResult alphabet.BuildResult, options EvaluationOptions) (Evaluation, error) {
	if !utf8.Valid(password) {
		return Evaluation{}, fmt.Errorf("password is not valid UTF-8")
	}

	result := Evaluation{
		Length: LengthResult{
			Count: utf8.RuneCount(password),
			Min:   options.MinLength,
			Max:   options.MaxLength,
		},
		Classes: make([]ClassResult, 0, len(buildResult.Classes)),
	}

	result.Length.Passed = result.Length.Count >= result.Length.Min && result.Length.Count <= result.Length.Max

	classIndexes := make(map[rune]int)

	for _, class := range buildResult.Classes {
		minimum, ok := options.ClassMinimums[class.Name]
		if !ok {
			return Evaluation{}, fmt.Errorf("missing minimum for class %q", class.Name)
		}

		classIndex := len(result.Classes)

		result.Classes = append(result.Classes, ClassResult{
			Name:    class.Name,
			Minimum: minimum,
		})

		for _, r := range class.Alphabet {
			classIndexes[r] = classIndex
		}
	}

	remaining := password

	for len(remaining) > 0 {
		r, size := utf8.DecodeRune(remaining)

		if classIndex, found := classIndexes[r]; found {
			result.Classes[classIndex].Count++
		}

		remaining = remaining[size:]
	}

	classesPassed := true

	for i := range result.Classes {
		result.Classes[i].Passed = result.Classes[i].Count >= result.Classes[i].Minimum

		if !result.Classes[i].Passed {
			classesPassed = false
		}
	}

	violations, err := Check(password, options.Rules)
	if err != nil {
		return Evaluation{}, fmt.Errorf("check prohibition rules: %w", err)
	}

	result.Violations = violations

	result.Passed = result.Length.Passed && classesPassed && len(result.Violations) == 0

	return result, nil
}
