package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type DiskQueue struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
}

func NewDiskQueue(path string, maxBytes int64) *DiskQueue {
	return &DiskQueue{path: path, maxBytes: maxBytes}
}

func (q *DiskQueue) read() ([]json.RawMessage, error) {
	data, err := os.ReadFile(q.path)
	if errors.Is(err, os.ErrNotExist) {
		return []json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	var records []json.RawMessage
	if len(data) == 0 {
		return records, nil
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (q *DiskQueue) write(records []json.RawMessage) error {
	if err := os.MkdirAll(filepath.Dir(q.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	for int64(len(data)) > q.maxBytes && len(records) > 1 {
		records = records[1:]
		data, err = json.Marshal(records)
		if err != nil {
			return err
		}
	}
	temporary := q.path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, q.path)
}

func (q *DiskQueue) Enqueue(value any) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	records, err := q.read()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return q.write(append(records, encoded))
}

func (q *DiskQueue) Snapshot(limit int) ([]json.RawMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	records, err := q.read()
	if err != nil {
		return nil, err
	}
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func (q *DiskQueue) Depth() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	records, err := q.read()
	if err != nil {
		return 0, err
	}
	return len(records), nil
}

func (q *DiskQueue) Ack(count int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	records, err := q.read()
	if err != nil {
		return err
	}
	if count > len(records) {
		count = len(records)
	}
	return q.write(records[count:])
}
