package generate

import (
	"testing"

	"github.com/Ahed11/password-policy/internal/alphabet"
	"github.com/Ahed11/password-policy/internal/random"
	"github.com/Ahed11/password-policy/internal/rules"
	"github.com/Ahed11/password-policy/internal/secret"
)

func BenchmarkGeneratePasswordLength20(b *testing.B) {
	buildResult, buildErrors := alphabet.Build(
		[]alphabet.ClassDefinition{
			{
				Name:     "digits",
				Alphabet: "0123456789",
			},
			{
				Name:     "lower",
				Alphabet: "abcdefghijklmnopqrstuvwxyz",
			},
			{
				Name:     "upper",
				Alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			},
			{
				Name:     "special",
				Alphabet: "!@#$%^&*()-_=+[]{};:,.?",
			},
		},
		"",
	)

	if len(buildErrors) != 0 {
		b.Fatalf("build benchmark alphabet: %v", buildErrors)
	}

	options := Options{
		MinLength: 20,
		MaxLength: 20,
		Attempts:  100,
		ClassMinimums: map[string]int{
			"digits":  2,
			"lower":   2,
			"upper":   2,
			"special": 1,
		},
		Rules: rules.Options{},
	}

	b.Run(
		"deterministic_source",
		func(b *testing.B) {
			benchmarkGeneratePassword(b, benchmarkZeroSource{}, buildResult, options)
		},
	)

	b.Run(
		"crypto_rand",
		func(b *testing.B) {
			benchmarkGeneratePassword(b, random.DefaultSource(), buildResult, options)
		},
	)
}

func benchmarkGeneratePassword(b *testing.B, source random.Source, buildResult alphabet.BuildResult, options Options) {
	b.Helper()

	b.ReportAllocs()
	b.SetBytes(20)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result, err := Generate(source, buildResult, options)
		if err != nil {
			b.Fatal(err)
		}

		secret.Zero(result.Password)
	}
}

type benchmarkZeroSource struct{}

func (benchmarkZeroSource) Read(data []byte) (int, error) {
	for i := range data {
		data[i] = 0
	}

	return len(data), nil
}
