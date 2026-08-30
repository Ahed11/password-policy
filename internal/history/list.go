package history

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	bolt "go.etcd.io/bbolt"
)

type storedRecord struct {
	key    uint64
	record Record
}

// List возвращает записи истории для указанного субъекта.
func (s *Store) List(subject string) ([]Record, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("list history records: store is not open")
	}

	stored := make([]storedRecord, 0)

	if err := s.db.View(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			if bucket == nil {
				return fmt.Errorf("records bucket does not exist")
			}

			return bucket.ForEach(
				func(key, value []byte) error {
					if value == nil {
						return fmt.Errorf("history record key %x contains a nested bucket", key)
					}

					if len(key) != 8 {
						return fmt.Errorf("history record has invalid key length %d", len(key))
					}

					var record Record

					if err := json.Unmarshal(value, &record); err != nil {
						return fmt.Errorf("decode history record key %x: %w", key, err)
					}

					if record.Subject != subject {
						return nil
					}

					stored = append(
						stored,
						storedRecord{
							key:    binary.BigEndian.Uint64(key),
							record: record,
						},
					)

					return nil
				},
			)
		},
	); err != nil {
		return nil, fmt.Errorf("list history records for subject %q: %w", subject, err)
	}

	sort.Slice(
		stored,
		func(i, j int) bool {
			left := stored[i]
			right := stored[j]

			if left.record.IssuedAt.Equal(
				right.record.IssuedAt,
			) {
				return left.key < right.key
			}

			return left.record.IssuedAt.Before(right.record.IssuedAt)
		},
	)

	records := make([]Record, 0, len(stored))

	for _, item := range stored {
		records = append(records, item.record)
	}

	return records, nil
}
