package history

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	bolt "go.etcd.io/bbolt"
)

func (s *Store) Accept(subject string, password []byte, window int, record Record) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("accept history record: store is not open")
	}

	if subject == "" {
		return false, fmt.Errorf("accept history record: subject must not be empty")
	}

	if window < 0 {
		return false, fmt.Errorf("accept history record: history window must not be negative, got %d", window)
	}

	if record.Subject != subject {
		return false, fmt.Errorf("accept history record: record subject %q does not match subject %q", record.Subject, subject)
	}

	data, err := json.Marshal(record)
	if err != nil {
		return false, fmt.Errorf("accept history record: encode record: %w", err)
	}

	accepted := false

	err = s.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			if bucket == nil {
				return fmt.Errorf("records bucket does not exist")
			}

			if window > 0 {
				stored := make([]storedRecord, 0)

				if err := bucket.ForEach(
					func(key, value []byte) error {
						if value == nil {
							return fmt.Errorf("history record key %x contains a nested bucket", key)
						}

						if len(key) != 8 {
							return fmt.Errorf("history record has invalid key length %d", len(key))
						}

						var existing Record

						if err := json.Unmarshal(value, &existing); err != nil {
							return fmt.Errorf("decode history record key %x: %w", key, err)
						}

						if existing.Subject != subject {
							return nil
						}

						stored = append(
							stored,
							storedRecord{
								key: binary.BigEndian.Uint64(
									key,
								),
								record: existing,
							},
						)

						return nil
					},
				); err != nil {
					return err
				}

				sort.Slice(
					stored,
					func(i, j int) bool {
						left := stored[i]
						right := stored[j]

						if left.record.IssuedAt.Equal(right.record.IssuedAt) {
							return left.key < right.key
						}

						return left.record.IssuedAt.Before(right.record.IssuedAt)
					},
				)

				start := len(stored) - window

				if start < 0 {
					start = 0
				}

				for i := len(stored) - 1; i >= start; i-- {
					if Matches(stored[i].record, password) {
						return nil
					}
				}
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

			accepted = true

			return nil
		},
	)
	if err != nil {
		return false, fmt.Errorf("accept history record for subject %q: %w", subject, err)
	}

	return accepted, nil
}
