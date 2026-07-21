package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestDiskQueueReplayAndAck(t *testing.T) {
	queue := NewDiskQueue(filepath.Join(t.TempDir(), "queue.json"), 4096)
	if err := queue.Enqueue(map[string]string{"id": "one"}); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(map[string]string{"id": "two"}); err != nil {
		t.Fatal(err)
	}
	records, err := queue.Snapshot(10)
	if err != nil || len(records) != 2 {
		t.Fatalf("unexpected snapshot: %d, %v", len(records), err)
	}
	depth, err := queue.Depth()
	if err != nil || depth != 2 {
		t.Fatalf("unexpected queue depth: %d, %v", depth, err)
	}
	var first map[string]string
	if err := json.Unmarshal(records[0], &first); err != nil || first["id"] != "one" {
		t.Fatalf("unexpected first event: %v, %v", first, err)
	}
	if err := queue.Ack(1); err != nil {
		t.Fatal(err)
	}
	records, _ = queue.Snapshot(10)
	if len(records) != 1 {
		t.Fatalf("expected one event, got %d", len(records))
	}
}

func TestDiskQueueEnforcesSize(t *testing.T) {
	queue := NewDiskQueue(filepath.Join(t.TempDir(), "queue.json"), 200)
	for i := 0; i < 20; i++ {
		if err := queue.Enqueue(map[string]string{"payload": "abcdefghijklmnopqrstuvwxyz"}); err != nil {
			t.Fatal(err)
		}
	}
	records, err := queue.Snapshot(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) >= 20 || len(records) == 0 {
		t.Fatalf("queue retention failed: %d records", len(records))
	}
}
