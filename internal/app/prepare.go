package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/dictionary"
	"github.com/Ahed11/password-policy/internal/generate"
	"github.com/Ahed11/password-policy/internal/policy"
	"github.com/Ahed11/password-policy/internal/rules"
)

// PrepareOptions задаёт дополнительные параметры подготовки политики.
type PrepareOptions struct {
	ContextValues []string
}

// Prepared содержит предварительно обработанные данные политики, готовые к генерации и проверке паролей.
type Prepared struct {
	Config        policy.Config
	Alphabet      alphabet.BuildResult
	ClassMinimums map[string]int
	Rules         rules.Options
	Generate      generate.Options
}

// Prepare подготавливает политику к использованию: строит алфавит, загружает словарь и формирует параметры правил и генерации.
func Prepare(ctx context.Context, cfg policy.Config, options PrepareOptions) (Prepared, error) {
	if ctx == nil {
		return Prepared{}, fmt.Errorf("prepare policy: context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return Prepared{}, fmt.Errorf("prepare policy: %w", err)
	}

	definitions := make([]alphabet.ClassDefinition, 0, len(cfg.Policy.Classes))

	classMinimums := make(map[string]int, len(cfg.Policy.Classes))

	for _, class := range cfg.Policy.Classes {
		definitions = append(
			definitions,
			alphabet.ClassDefinition{
				Name:     class.Name,
				Alphabet: class.Alphabet,
			},
		)

		classMinimums[class.Name] = class.Min
	}

	buildResult, buildErrors := alphabet.Build(definitions, cfg.Policy.Exclude)

	if len(buildErrors) > 0 {
		return Prepared{}, fmt.Errorf("prepare policy alphabet: %w", errors.Join(buildErrors...))
	}

	if err := ctx.Err(); err != nil {
		return Prepared{}, fmt.Errorf("prepare policy: %w", err)
	}

	dictionaryConfig := cfg.Policy.Forbid.Dictionary

	contextCaseInsensitive := dictionaryConfig.CaseInsensitive
	contextLeet := dictionaryConfig.Leet

	var matcher *dictionary.Matcher

	if dictionaryConfig.Path != "" {
		var loadErr error

		matcher, loadErr = dictionary.Load(dictionaryConfig.Path, dictionaryConfig.MinLength, dictionaryConfig.CaseInsensitive, dictionaryConfig.Leet)
		if loadErr != nil {
			return Prepared{}, fmt.Errorf("prepare dictionary: %w", loadErr)
		}
	}

	var keyboardLayoutTables map[string][][]rune

	if cfg.Policy.Forbid.Sequences.Keyboard > 0 {
		var loadErr error

		keyboardLayoutTables, loadErr = rules.LoadKeyboardLayoutFiles(cfg.Policy.Forbid.Sequences.Layouts)
		if loadErr != nil {
			return Prepared{}, fmt.Errorf("prepare keyboard layouts: %w", loadErr)
		}
	}

	if err := ctx.Err(); err != nil {
		return Prepared{}, fmt.Errorf("prepare policy: %w", err)
	}

	ruleOptions := rules.Options{
		RepeatRun:            cfg.Policy.Forbid.RepeatRun,
		RepeatTotal:          cfg.Policy.Forbid.RepeatTotal,
		AlphabetSequence:     cfg.Policy.Forbid.Sequences.Alphabet,
		KeyboardSequence:     cfg.Policy.Forbid.Sequences.Keyboard,
		KeyboardLayouts:      append([]string(nil), cfg.Policy.Forbid.Sequences.Layouts...),
		KeyboardLayoutTables: keyboardLayoutTables,

		Dictionary: matcher,

		ContextValues:          append([]string(nil), options.ContextValues...),
		ContextMinLength:       cfg.Policy.Forbid.Context.MinLength,
		ContextCaseInsensitive: contextCaseInsensitive,
		ContextLeet:            contextLeet,
	}

	generateOptions := generate.Options{
		MinLength:     cfg.Policy.Length.Min,
		MaxLength:     cfg.Policy.Length.Max,
		Attempts:      cfg.Policy.Attempts,
		ClassMinimums: classMinimums,
		Rules:         ruleOptions,
	}

	return Prepared{
		Config:        cfg,
		Alphabet:      buildResult,
		ClassMinimums: classMinimums,
		Rules:         ruleOptions,
		Generate:      generateOptions,
	}, nil
}
