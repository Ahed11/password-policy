package history

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	bolt "go.etcd.io/bbolt"
)

type VerifyIssue struct {
	Key     string `json:"key"`
	Subject string `json:"subject,omitempty"`
	Message string `json:"message"`
}

type VerifyResult struct {
	Checked int           `json:"checked"`
	Issues  []VerifyIssue `json:"issues"`
}

func (s *Store) Verify() (VerifyResult, error) {
	if s == nil || s.db == nil {
		return VerifyResult{}, fmt.Errorf("verify history: store is not open")
	}

	result := VerifyResult{
		Issues: make([]VerifyIssue, 0),
	}

	err := s.db.View(
		func(tx *bolt.Tx) error {
			for checkErr := range tx.Check() {
				result.Issues = append(
					result.Issues,
					VerifyIssue{
						Message: fmt.Sprintf("bbolt consistency: %v", checkErr),
					},
				)
			}

			bucket := tx.Bucket(recordsBucket)
			if bucket == nil {
				return fmt.Errorf("records bucket does not exist")
			}

			return bucket.ForEach(
				func(key, value []byte) error {
					keyText := hex.EncodeToString(key)

					result.Checked++

					if value == nil {
						result.Issues = append(
							result.Issues,
							VerifyIssue{
								Key:     keyText,
								Message: "record entry contains a nested bucket",
							},
						)

						return nil
					}

					if len(key) != 8 {
						result.Issues = append(
							result.Issues,
							VerifyIssue{
								Key:     keyText,
								Message: fmt.Sprintf("invalid record key length: got %d, want 8", len(key)),
							},
						)
					}

					var record Record

					if err := json.Unmarshal(value, &record); err != nil {
						result.Issues = append(
							result.Issues,
							VerifyIssue{
								Key:     keyText,
								Message: fmt.Sprintf("invalid record JSON: %v", err),
							},
						)

						return nil
					}

					verifyRecord(&result, keyText, record)

					return nil
				},
			)
		},
	)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("verify history: %w", err)
	}

	sort.Slice(
		result.Issues,
		func(i, j int) bool {
			left := result.Issues[i]
			right := result.Issues[j]

			if left.Key != right.Key {
				return left.Key < right.Key
			}

			if left.Subject != right.Subject {
				return left.Subject < right.Subject
			}

			return left.Message < right.Message
		},
	)

	return result, nil
}

func verifyRecord(result *VerifyResult, key string, record Record) {
	addIssue := func(message string) {
		result.Issues = append(
			result.Issues,
			VerifyIssue{
				Key:     key,
				Subject: record.Subject,
				Message: message,
			},
		)
	}

	if record.Subject == "" {
		addIssue("subject must not be empty")
	}

	if len(record.Salt) < SaltSize {
		addIssue(
			fmt.Sprintf("salt is too short: got %d bytes, want at least %d", len(record.Salt), SaltSize))
	}

	if len(record.Hash) != sha256.Size {
		addIssue(fmt.Sprintf("invalid hash length: got %d bytes, want %d", len(record.Hash), sha256.Size))
	}

	if record.IssuedAt.IsZero() {
		addIssue("issued_at must not be zero")
	} else {
		_, offset := record.IssuedAt.Zone()

		if offset != 0 {
			addIssue("issued_at must be stored in UTC")
		}
	}

	if !record.ExpiresAt.IsZero() {
		_, offset := record.ExpiresAt.Zone()

		if offset != 0 {
			addIssue("expires_at must be stored in UTC")
		}

		if !record.IssuedAt.IsZero() &&
			record.ExpiresAt.Before(record.IssuedAt) {
			addIssue("expires_at must not be before issued_at")
		}
	}

	if record.PolicyName == "" {
		addIssue("policy_name must not be empty")
	}

	if record.PolicyVersion == "" {
		addIssue("policy_version must not be empty")
	}
}
