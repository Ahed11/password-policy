package history

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

const (
	databaseFileName = "history.db"
	databaseFileMode = 0o600
	storeDirMode     = 0o700
)

var recordsBucket = []byte("records")

type Store struct {
	db *bolt.DB
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("open history store: path must not be empty")
	}

	if err := os.MkdirAll(path, storeDirMode); err != nil {
		return nil, fmt.Errorf("open history store: create directory %q: %w", path, err)
	}

	databasePath := filepath.Join(path, databaseFileName)

	db, err := bolt.Open(databasePath, databaseFileMode, nil)
	if err != nil {
		return nil, fmt.Errorf("open history store database %q: %w", databasePath, err)
	}

	if err := db.Update(
		func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists(recordsBucket)
			if err != nil {
				return fmt.Errorf("create records bucket: %w", err)
			}

			return nil
		},
	); err != nil {
		closeErr := db.Close()

		if closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("initialize history store %q: %w", databasePath, err),
				fmt.Errorf("close history store after initialization failure: %w", closeErr),
			)
		}

		return nil, fmt.Errorf("initialize history store %q: %w", databasePath, err)
	}

	return &Store{
		db: db,
	}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}

	db := s.db
	s.db = nil

	if err := db.Close(); err != nil {
		return fmt.Errorf("close history store: %w", err)
	}

	return nil
}
