package rules

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"unicode/utf8"
)

type keyboardLayout struct {
	name string
	rows [][]rune
}

var qwertyLayout = keyboardLayout{
	name: "qwerty",
	rows: [][]rune{
		[]rune("qwertyuiop"),
		[]rune("asdfghjkl"),
		[]rune("zxcvbnm"),
	},
}

var jcukenLayout = keyboardLayout{
	name: "jcuken",
	rows: [][]rune{
		[]rune("йцукенгшщзхъ"),
		[]rune("фывапролджэ"),
		[]rune("ячсмитьбю"),
	},
}

func getKeyboardLayout(name string) (keyboardLayout, bool) {
	switch name {
	case "qwerty":
		return qwertyLayout, true
	case "jcuken":
		return jcukenLayout, true
	default:
		return keyboardLayout{}, false
	}
}

func loadKeyboardLayoutFile(path string) (layout keyboardLayout, err error) {
	file, err := os.Open(path)
	if err != nil {
		return keyboardLayout{}, fmt.Errorf("open keyboard layout file %q: %w", path, err)
	}

	defer func() {
		err = errors.Join(err, file.Close())
	}()

	rows := make([][]rune, 0)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		rowBytes := scanner.Bytes()

		if !utf8.Valid(rowBytes) {
			return keyboardLayout{}, fmt.Errorf("keyboard layout file %q contains invalid UTF-8", path)
		}

		if len(rowBytes) == 0 {
			continue
		}

		rows = append(rows, []rune(string(rowBytes)))
	}

	if err := scanner.Err(); err != nil {
		return keyboardLayout{}, fmt.Errorf("read keyboard layout file %q: %w", path, err)
	}

	if len(rows) == 0 {
		return keyboardLayout{}, fmt.Errorf("keyboard layout file %q contains no rows", path)
	}

	return keyboardLayout{
		name: path,
		rows: rows,
	}, nil
}

// LoadKeyboardLayoutFiles загружает пользовательские таблицы клавиатурных раскладок.
// Встроенные раскладки пропускаются и не читаются как файлы.
func LoadKeyboardLayoutFiles(names []string) (map[string][][]rune, error) {
	tables := make(map[string][][]rune)

	for _, name := range names {
		if _, builtIn := getKeyboardLayout(name); builtIn {
			continue
		}

		layout, err := loadKeyboardLayoutFile(name)
		if err != nil {
			return nil, fmt.Errorf("load keyboard layout %q: %w", name, err)
		}

		rows := make([][]rune, len(layout.rows))

		for rowIndex := range layout.rows {
			rows[rowIndex] = append([]rune(nil), layout.rows[rowIndex]...)
		}

		tables[name] = rows
	}

	return tables, nil
}
