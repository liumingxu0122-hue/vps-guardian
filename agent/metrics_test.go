package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEmptyHelperSnapshotProducesArrayNotNull(t *testing.T) {
	snapshot := Snapshot{
		PortTraffic: normalizePortTrafficObservations(nil),
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"port_traffic":[]`)) {
		t.Fatalf("empty port traffic must be an array: %s", encoded)
	}
}
