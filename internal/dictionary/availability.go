package dictionary

import (
	"fmt"
	"os"
)

func CheckAvailability(path string) error {
	if path == "" {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("dictionary path %q cannot be opened: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("dictionary path %q cannot be inspected: %w", path, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("dictionary path %q is not a regular file", path)
	}

	return nil
}
