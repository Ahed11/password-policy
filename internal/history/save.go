package history

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// Save сохраняет новую запись истории в хранилище.
func (s *Store) Save(record Record) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("save history record: store is not open")
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("save history record: encode record: %w", err)
	}

	if err := s.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			if bucket == nil {
				return fmt.Errorf("records bucket does not exist")
			}

			sequence, err := bucket.NextSequence()
			if err != nil {
				return fmt.Errorf("allocate record sequence: %w", err)
			}

			var key [8]byte

			binary.BigEndian.PutUint64(key[:], sequence)

			if err := bucket.Put(key[:], data); err != nil {
				return fmt.Errorf("store history record: %w", err)
			}

			return nil
		},
	); err != nil {
		return fmt.Errorf("save history record: %w", err)
	}

	return nil
}
