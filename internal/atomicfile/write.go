package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func Write(path string, data []byte, perm fs.FileMode) (returnErr error) {
	if path == "" {
		return fmt.Errorf("atomic write: path must not be empty")
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tempFile, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("atomic write %q: create temporary file: %w", path, err)
	}

	tempPath := tempFile.Name()

	closed := false
	committed := false

	defer func() {
		var cleanupErrors []error

		if !closed {
			if err := tempFile.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("close temporary file %q: %w", tempPath, err))
			}

			closed = true
		}

		if !committed {
			if err := os.Remove(tempPath); err != nil &&
				!errors.Is(err, fs.ErrNotExist) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove temporary file %q: %w", tempPath, err))
			}
		}

		if len(cleanupErrors) > 0 {
			allErrors := make([]error, 0, len(cleanupErrors)+1)

			if returnErr != nil {
				allErrors = append(allErrors, returnErr)
			}

			allErrors = append(allErrors, cleanupErrors...)

			returnErr = errors.Join(allErrors...)
		}
	}()

	written, err := tempFile.Write(data)
	if err != nil {
		return fmt.Errorf("atomic write %q: write temporary file: %w", path, err)
	}

	if written != len(data) {
		return fmt.Errorf("atomic write %q: write temporary file: wrote %d of %d bytes: %w", path, written, len(data), io.ErrShortWrite)
	}

	if err := tempFile.Chmod(perm); err != nil {
		return fmt.Errorf("atomic write %q: set temporary file permissions: %w", path, err)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("atomic write %q: sync temporary file: %w", path, err)
	}

	if err := tempFile.Close(); err != nil {
		closed = true

		return fmt.Errorf("atomic write %q: close temporary file: %w", path, err)
	}

	closed = true

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("atomic write %q: rename temporary file: %w", path, err)
	}

	committed = true

	return nil
}
