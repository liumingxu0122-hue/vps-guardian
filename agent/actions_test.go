package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnknownAndNonAllowlistedActionsAreRejected(t *testing.T) {
	config := Config{StateFile: filepath.Join(t.TempDir(), "state.json"), ContainerAllowlist: []string{"allowed-container"}}
	registry := NewActionRegistry(config)
	unknown := registry.Execute(context.Background(), Task{ID: "unknown", Action: "shell", Parameters: map[string]string{"target": "anything"}})
	if unknown.Success || unknown.Message != "action is not registered" {
		t.Fatalf("unknown action was not rejected: %+v", unknown)
	}
	restart := registry.Execute(context.Background(), Task{ID: "restart", Action: "restart_container", Parameters: map[string]string{"target": "not-allowed", "dry_run": "true"}})
	if restart.Success || restart.Message != "target is not allowlisted" {
		t.Fatalf("non-allowlisted target was not rejected: %+v", restart)
	}
}

func TestCompletedTaskReplayIsAcknowledgedWithoutExecutingAgain(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target := strings.Replace(server.URL, "[::]", "localhost", 1)
	registry := NewActionRegistry(Config{
		StateFile:       filepath.Join(t.TempDir(), "state.json"),
		CommandTimeout:  Duration(time.Second),
		LocalHealthURLs: []string{target},
	})
	task := Task{
		ID: "replayed-health-check", Action: "local_health_check",
		Parameters: map[string]string{"target": target, "dry_run": "false"},
	}
	first := registry.Execute(context.Background(), task)
	second := registry.Execute(context.Background(), task)
	if !first.Success || !second.Success || second.Message != "task was already completed" {
		t.Fatalf("completed task replay was not idempotent: first=%+v second=%+v", first, second)
	}
	if requests.Load() != 1 {
		t.Fatalf("replayed task executed more than once: %d requests", requests.Load())
	}
}

func TestCleanupCacheOnlyRemovesExpiredAllowlistedFiles(t *testing.T) {
	cache := t.TempDir()
	oldFile := filepath.Join(cache, "expired.cache")
	recentFile := filepath.Join(cache, "recent.cache")
	if err := os.WriteFile(oldFile, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recentFile, []byte("recent"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	registry := NewActionRegistry(Config{
		StateFile: filepath.Join(t.TempDir(), "state.json"), CacheAllowlist: []string{cache},
		CacheRetention: Duration(time.Hour),
	})
	dryRun := registry.Execute(context.Background(), Task{
		ID: "cache-dry-run", Action: "cleanup_cache",
		Parameters: map[string]string{"target": cache, "dry_run": "true"},
	})
	if !dryRun.Success || dryRun.Before["eligible_files"] != "1" {
		t.Fatalf("unexpected dry-run result: %+v", dryRun)
	}
	if _, err := os.Stat(oldFile); err != nil {
		t.Fatalf("dry-run removed a file: %v", err)
	}
	executed := registry.Execute(context.Background(), Task{
		ID: "cache-execute", Action: "cleanup_cache",
		Parameters: map[string]string{"target": cache, "dry_run": "false"},
	})
	if !executed.Success || executed.After["removed_files"] != "1" {
		t.Fatalf("unexpected cleanup result: %+v", executed)
	}
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatalf("expired cache file still exists: %v", err)
	}
	if _, err := os.Stat(recentFile); err != nil {
		t.Fatalf("recent cache file was removed: %v", err)
	}
}

func TestLocalHealthCheckWaitsForServiceReadiness(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) < 3 {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	target := strings.Replace(server.URL, "[::]", "localhost", 1)
	registry := NewActionRegistry(Config{
		StateFile:      filepath.Join(t.TempDir(), "state.json"),
		CommandTimeout: Duration(3 * time.Second),
		LocalHealthURLs: []string{
			target,
		},
	})
	result := registry.Execute(context.Background(), Task{
		ID: "health-after-restart", Action: "local_health_check",
		Parameters: map[string]string{"target": target, "dry_run": "false"},
	})
	if !result.Success {
		t.Fatalf("health check did not wait for readiness: %+v", result)
	}
	attempts, err := strconv.Atoi(result.After["attempts"])
	if err != nil || attempts != 3 {
		t.Fatalf("unexpected retry count: %+v", result.After)
	}
	if result.After["http_status"] != "200 OK" {
		t.Fatalf("unexpected final status: %+v", result.After)
	}
}

func TestLocalHealthCheckStopsAtCommandTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	target := strings.Replace(server.URL, "[::]", "localhost", 1)
	registry := NewActionRegistry(Config{
		StateFile:      filepath.Join(t.TempDir(), "state.json"),
		CommandTimeout: Duration(600 * time.Millisecond),
		LocalHealthURLs: []string{
			target,
		},
	})
	started := time.Now()
	result := registry.Execute(context.Background(), Task{
		ID: "health-timeout", Action: "local_health_check",
		Parameters: map[string]string{"target": target, "dry_run": "false"},
	})
	if result.Success || result.Message != "local health check returned 503" {
		t.Fatalf("persistent failure was not bounded: %+v", result)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("health check exceeded its bounded timeout: %s", elapsed)
	}
}

func TestVerifiedSnapshotRejectsHashMismatchAndSymbolicLink(t *testing.T) {
	root := t.TempDir()
	snapshotDirectory := filepath.Join(root, "staging-baseline")
	if err := os.Mkdir(snapshotDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(snapshotDirectory, "Caddyfile")
	manifest := candidate + ".sha256"
	baseline := []byte(":8082 { respond \"healthy\" }\n")
	if err := os.WriteFile(candidate, baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(sha256String(baseline)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := readVerifiedSnapshot(root, "staging-baseline", candidate)
	if err != nil || string(verified) != string(baseline) {
		t.Fatalf("valid snapshot was rejected: %v", err)
	}
	if err := os.WriteFile(candidate, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readVerifiedSnapshot(root, "staging-baseline", candidate); err == nil || err.Error() != "snapshot hash mismatch" {
		t.Fatalf("tampered snapshot was not rejected: %v", err)
	}
	if err := os.Remove(candidate); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, candidate); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := readVerifiedSnapshot(root, "staging-baseline", candidate); err == nil || err.Error() != "snapshot is not a regular file" {
		t.Fatalf("symbolic-link snapshot was not rejected: %v", err)
	}
}
