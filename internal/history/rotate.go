package history

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

const RotationReasonExpired = "expired"

type RotationItem struct {
	Subject   string    `json:"subject"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

type RotationPlan struct {
	Items    []RotationItem `json:"items"`
	Warnings []string       `json:"warnings"`
}

func (s *Store) PlanRotation(now time.Time) (RotationPlan, error) {
	if s == nil || s.db == nil {
		return RotationPlan{}, fmt.Errorf("plan rotation: store is not open")
	}

	now = now.UTC()

	recordsBySubject := make(map[string][]storedRecord)

	err := s.db.View(
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

					item := storedRecord{
						key:    binary.BigEndian.Uint64(key),
						record: record,
					}

					recordsBySubject[record.Subject] = append(recordsBySubject[record.Subject], item)

					return nil
				},
			)
		},
	)
	if err != nil {
		return RotationPlan{}, fmt.Errorf("plan rotation: %w", err)
	}

	plan := RotationPlan{
		Items:    make([]RotationItem, 0),
		Warnings: make([]string, 0),
	}

	for subject, records := range recordsBySubject {
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

		latest := records[len(records)-1].record

		issuedAt := latest.IssuedAt.UTC()

		if now.Before(issuedAt) {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("clock moved backwards for subject %q: now %s is before latest issued_at %s", subject, now.Format(time.RFC3339Nano), issuedAt.Format(time.RFC3339Nano)))

			continue
		}

		if latest.ExpiresAt.IsZero() {
			continue
		}

		expiresAt := latest.ExpiresAt.UTC()

		if now.Before(expiresAt) {
			continue
		}

		plan.Items = append(
			plan.Items,
			RotationItem{
				Subject:   subject,
				IssuedAt:  issuedAt,
				ExpiresAt: expiresAt,
				Reason:    RotationReasonExpired,
			},
		)
	}

	sort.Slice(
		plan.Items,
		func(i, j int) bool {
			left := plan.Items[i]
			right := plan.Items[j]

			if !left.ExpiresAt.Equal(right.ExpiresAt) {
				return left.ExpiresAt.Before(right.ExpiresAt)
			}

			if left.Subject != right.Subject {
				return left.Subject < right.Subject
			}

			return left.IssuedAt.Before(right.IssuedAt)
		},
	)

	sort.Strings(plan.Warnings)

	return plan, nil
}
