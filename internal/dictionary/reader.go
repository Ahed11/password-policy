package dictionary

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

func readWords(path string, minLength int, caseInsensitive bool) (words []string, err error) {
	if path == "" {
		return nil, nil
	}

	if err := CheckAvailability(path); err != nil {
		return nil, fmt.Errorf("check dictionary availability: %w", err)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open dictionary %q: %w", path, err)
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close dictionary %q: %w", path, closeErr))
		}
	}()

	reader := bufio.NewReader(file)

	for {
		line, readErr := reader.ReadString('\n')

		if len(line) > 0 {
			if strings.HasSuffix(line, "\n") {
				line = strings.TrimSuffix(line, "\n")
				line = strings.TrimSuffix(line, "\r")
			}

			if line != "" {
				if caseInsensitive {
					line = strings.ToLower(line)
				}

				if utf8.RuneCountInString(line) >= minLength {
					words = append(words, line)
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}

			return nil, fmt.Errorf("read dictionary %q: %w", path, readErr)
		}
	}

	return words, nil
}
