package dictionary

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	benchmarkDictionarySmallWordCount = 1_000
	benchmarkDictionaryWordCount      = 1_000_000
)

var (
	benchmarkLoadedMatcher *Matcher
	benchmarkSearchMatches []Match
)

func BenchmarkLoadDictionaryMillionWords(b *testing.B) {
	path := writeBenchmarkDictionary(b, benchmarkDictionaryWordCount)

	b.ReportAllocs()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		matcher, err := Load(path, 4, true, false)
		if err != nil {
			b.Fatal(err)
		}

		benchmarkLoadedMatcher = matcher
	}
}

func BenchmarkDictionarySearch(b *testing.B) {
	smallPath := writeBenchmarkDictionary(b, benchmarkDictionarySmallWordCount)

	largePath := writeBenchmarkDictionary(b, benchmarkDictionaryWordCount)

	smallMatcher, err := Load(smallPath, 4, true, false)
	if err != nil {
		b.Fatalf("load small benchmark dictionary: %v", err)
	}

	largeMatcher, err := Load(largePath, 4, true, false)
	if err != nil {
		b.Fatalf("load large benchmark dictionary: %v", err)
	}

	password := []byte("xxBENCHMARKWORD999yy")

	b.Run("1000_words", func(b *testing.B) {
		benchmarkDictionaryFind(b, smallMatcher, password)
	},
	)

	b.Run("1000000_words", func(b *testing.B) {
		benchmarkDictionaryFind(b, largeMatcher, password)
	},
	)
}

func benchmarkDictionaryFind(b *testing.B, matcher *Matcher, password []byte) {
	b.Helper()

	matches := matcher.Find(password)
	if len(matches) == 0 {
		b.Fatal("benchmark password must contain a dictionary match")
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(password)))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchmarkSearchMatches = matcher.Find(password)
	}
}

func writeBenchmarkDictionary(b *testing.B, wordCount int) string {
	b.Helper()

	path := filepath.Join(b.TempDir(), "dictionary.txt")

	file, err := os.Create(path)
	if err != nil {
		b.Fatalf("create benchmark dictionary: %v", err)
	}

	writer := bufio.NewWriterSize(file, 1024*1024)

	for i := 0; i < wordCount; i++ {
		word := make([]byte, 0, 24)

		word = append(word, "benchmarkword"...)

		word = strconv.AppendInt(word, int64(i), 10)

		word = append(word, '\n')

		if _, err := writer.Write(word); err != nil {
			_ = file.Close()

			b.Fatalf("write benchmark dictionary: %v", err)
		}
	}

	if err := writer.Flush(); err != nil {
		_ = file.Close()

		b.Fatalf("flush benchmark dictionary: %v", err)
	}

	if err := file.Close(); err != nil {
		b.Fatalf("close benchmark dictionary: %v", err)
	}

	return path
}
