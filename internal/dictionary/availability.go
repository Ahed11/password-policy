package dictionary

import (
	"errors"
	"fmt"
	"os"
)

// CheckAvailability проверяет доступность и читаемость файла словаря.
func CheckAvailability(path string) (err error) {
	if path == "" {
		return nil
	}

	var file *os.File

	file, err = os.Open(path)
	if err != nil {
		return fmt.Errorf("dictionary path %q cannot be opened: %w", path, err)
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("dictionary path %q cannot be inspected: %w", path, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("dictionary path %q is not a regular file", path)
	}

	return nil
}
