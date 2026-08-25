package generate

import "unicode/utf8"

func encodeRunes(values []rune) []byte {
	var result []byte

	for _, r := range values {
		result = utf8.AppendRune(result, r)
	}

	return result
}
