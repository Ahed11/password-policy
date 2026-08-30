package rules

import (
	"fmt"

	"github.com/Ahed11/password-policy/internal/dictionary"
)

// Violation описывает одно нарушение правила пароля с указанием позиции и длины.
type Violation struct {
	Rule   string
	Offset int
	Length int
	Layout string
}

// Options задаёт параметры проверки правил пароля.
type Options struct {
	RepeatRun            int
	RepeatTotal          bool
	AlphabetSequence     int
	KeyboardSequence     int
	KeyboardLayouts      []string
	KeyboardLayoutTables map[string][][]rune

	Dictionary *dictionary.Matcher

	ContextValues          []string
	ContextMinLength       int
	ContextCaseInsensitive bool
	ContextLeet            bool
}

// Check проверяет пароль по настроенным правилам и возвращает найденные нарушения.
func Check(password []byte, options Options) ([]Violation, error) {
	var violations []Violation

	for _, violation := range checkRepeatRun(
		password,
		options.RepeatRun,
	) {
		violations = append(violations, Violation{
			Rule:   "repeat_run",
			Offset: violation.offset,
			Length: violation.length,
		})
	}

	for _, violation := range checkRepeatTotal(
		password,
		options.RepeatTotal,
	) {
		violations = append(violations, Violation{
			Rule:   "repeat_total",
			Offset: violation.offset,
			Length: violation.length,
		})
	}

	for _, violation := range checkAlphabetSequence(
		password,
		options.AlphabetSequence,
	) {
		violations = append(violations, Violation{
			Rule:   "sequences.alphabet",
			Offset: violation.offset,
			Length: violation.length,
		})
	}

	if options.KeyboardSequence > 0 {
		for _, layoutName := range options.KeyboardLayouts {
			layout, found := getKeyboardLayout(layoutName)
			if !found {
				rows, exists := options.KeyboardLayoutTables[layoutName]
				if !exists {
					return nil, fmt.Errorf("unknown keyboard layout %q", layoutName)
				}

				layout = keyboardLayout{
					name: layoutName,
					rows: rows,
				}
			}

			for _, violation := range checkKeyboardSequence(password, options.KeyboardSequence, layout) {
				violations = append(violations, Violation{
					Rule:   "sequences.keyboard",
					Offset: violation.offset,
					Length: violation.length,
					Layout: violation.layout,
				})
			}
		}
	}

	for _, violation := range checkDictionary(password, options.Dictionary) {
		violations = append(violations, Violation{
			Rule:   "dictionary",
			Offset: violation.offset,
			Length: violation.length,
		})
	}

	for _, violation := range checkContext(password, options.ContextValues, options.ContextMinLength, options.ContextCaseInsensitive, options.ContextLeet) {
		violations = append(violations, Violation{
			Rule:   "context",
			Offset: violation.offset,
			Length: violation.length,
		})
	}

	return violations, nil
}
