package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrMetadataNotFound возвращается, когда metadata истории отсутствуют в хранилище.
var ErrMetadataNotFound = errors.New("history_metadata_not_found")

var (
	metadataBucket    = []byte("metadata")
	metadataConfigKey = []byte("config")
)

// Metadata содержит параметры окна и срока хранения истории.
type Metadata struct {
	HistoryWindow int
	HistoryTTL    time.Duration
}

type storedMetadata struct {
	HistoryWindow   int   `json:"history_window"`
	HistoryTTLNanos int64 `json:"history_ttl_ns"`
}

// SaveMetadata сохраняет metadata истории в хранилище.
func (s *Store) SaveMetadata(metadata Metadata) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("save history metadata: store is not open")
	}

	if err := validateMetadata(metadata); err != nil {
		return fmt.Errorf("save history metadata: %w", err)
	}

	if err := s.db.Update(
		func(tx *bolt.Tx) error {
			return putMetadata(tx, metadata)
		},
	); err != nil {
		return fmt.Errorf("save history metadata: %w", err)
	}

	return nil
}

// LoadMetadata загружает metadata истории из хранилища.
func (s *Store) LoadMetadata() (Metadata, error) {
	if s == nil || s.db == nil {
		return Metadata{}, fmt.Errorf("load history metadata: store is not open")
	}

	var metadata Metadata

	err := s.db.View(
		func(tx *bolt.Tx) error {
			loaded, err := loadMetadata(tx)
			if err != nil {
				return err
			}

			metadata = loaded

			return nil
		},
	)
	if err != nil {
		return Metadata{}, fmt.Errorf("load history metadata: %w", err)
	}

	return metadata, nil
}

func putMetadata(tx *bolt.Tx, metadata Metadata) error {
	if err := validateMetadata(metadata); err != nil {
		return err
	}

	bucket, err := tx.CreateBucketIfNotExists(metadataBucket)
	if err != nil {
		return fmt.Errorf("create metadata bucket: %w", err)
	}

	stored := storedMetadata{
		HistoryWindow:   metadata.HistoryWindow,
		HistoryTTLNanos: int64(metadata.HistoryTTL),
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("encode history metadata: %w", err)
	}

	if err := bucket.Put(metadataConfigKey, data); err != nil {
		return fmt.Errorf("store history metadata: %w", err)
	}

	return nil
}

func loadMetadata(tx *bolt.Tx) (Metadata, error) {
	bucket := tx.Bucket(metadataBucket)
	if bucket == nil {
		return Metadata{}, ErrMetadataNotFound
	}

	data := bucket.Get(metadataConfigKey)
	if data == nil {
		return Metadata{}, ErrMetadataNotFound
	}

	var stored storedMetadata

	if err := json.Unmarshal(data, &stored); err != nil {
		return Metadata{}, fmt.Errorf("decode history metadata: %w", err)
	}

	metadata := Metadata{
		HistoryWindow: stored.HistoryWindow,
		HistoryTTL:    time.Duration(stored.HistoryTTLNanos),
	}

	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, fmt.Errorf("invalid history metadata: %w", err)
	}

	return metadata, nil
}

func validateMetadata(metadata Metadata) error {
	if metadata.HistoryWindow < 0 {
		return fmt.Errorf("history window must not be negative, got %d", metadata.HistoryWindow)
	}

	if metadata.HistoryTTL < 0 {
		return fmt.Errorf("history ttl must not be negative")
	}

	return nil
}
