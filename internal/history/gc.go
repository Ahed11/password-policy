package history

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// GCResult содержит количество удалённых и сохранённых записей после очистки истории.
type GCResult struct {
	Deleted int
	Kept    int
}

// GC удаляет устаревшие записи истории, сохраняя записи, необходимые для защищённого окна.
func (s *Store) GC(now time.Time, ttl time.Duration, window int) (GCResult, error) {
	if s == nil || s.db == nil {
		return GCResult{}, fmt.Errorf("gc history: store is not open")
	}

	if ttl < 0 {
		return GCResult{}, fmt.Errorf("gc history: ttl must not be negative")
	}

	if window < 0 {
		return GCResult{}, fmt.Errorf("gc history: history window must not be negative, got %d", window)
	}

	now = now.UTC()

	var result GCResult

	err := s.db.Update(
		func(tx *bolt.Tx) error {
			bucket := tx.Bucket(recordsBucket)
			if bucket == nil {
				return fmt.Errorf("records bucket does not exist")
			}

			recordsBySubject := make(map[string][]storedRecord)

			allRecords := make([]storedRecord, 0)

			if err := bucket.ForEach(
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

					item := storedRecord{
						key:    binary.BigEndian.Uint64(key),
						record: record,
					}

					allRecords = append(allRecords, item)

					recordsBySubject[record.Subject] = append(recordsBySubject[record.Subject], item)

					return nil
				},
			); err != nil {
				return err
			}

			protected := make(map[uint64]struct{})

			for subject := range recordsBySubject {
				records := recordsBySubject[subject]

				sort.Slice(
					records,
					func(i, j int) bool {
						left := records[i]
						right := records[j]

						if left.record.IssuedAt.Equal(right.record.IssuedAt) {
							return left.key < right.key
						}

						return left.record.IssuedAt.Before(right.record.IssuedAt)
					},
				)

				start := len(records) - window

				if start < 0 {
					start = 0
				}

				for i := start; i < len(records); i++ {
					protected[records[i].key] = struct{}{}
				}
			}

			keysToDelete := make([]uint64, 0)

			for _, item := range allRecords {
				if _, ok := protected[item.key]; ok {
					continue
				}

				if ttl == 0 {
					continue
				}

				if now.Before(item.record.IssuedAt) {
					continue
				}

				expiresAt := item.record.IssuedAt.Add(ttl)

				if now.Before(expiresAt) {
					continue
				}

				keysToDelete = append(keysToDelete, item.key)
			}

			for _, sequence := range keysToDelete {
				var key [8]byte

				binary.BigEndian.PutUint64(key[:], sequence)

				if err := bucket.Delete(key[:]); err != nil {
					return fmt.Errorf("delete history record key %d: %w", sequence, err)
				}
			}

			result.Deleted = len(keysToDelete)
			result.Kept = len(allRecords) - len(keysToDelete)

			return nil
		},
	)
	if err != nil {
		return GCResult{}, fmt.Errorf("gc history: %w", err)
	}

	return result, nil
}
