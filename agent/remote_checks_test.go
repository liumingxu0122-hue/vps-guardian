package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoteHTTPCheckUsesAllowlistAndReturnsBoundedEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Fatal("remote check sent forbidden credentials")
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("healthy"))
	}))
	defer server.Close()
	check := RemoteCheck{
		ID:             "check-http",
		Kind:           "http",
		TimeoutSeconds: 5,
		Configuration: map[string]any{
			"target":             server.URL,
			"expected_statuses":  []any{float64(200)},
			"expected_contains":  "healthy",
			"allowed_networks":   []any{"127.0.0.1/32"},
			"max_response_bytes": float64(1024),
		},
	}
	results := runRemoteChecks(context.Background(), Config{}, []RemoteCheck{check})
	if len(results) != 1 || results[0]["status"] != "ok" {
		t.Fatalf("expected successful check, got %#v", results)
	}
	details := results[0]["details"].(map[string]any)
	if details["content_length"] != 7 {
		t.Fatalf("unexpected evidence: %#v", details)
	}
}

func TestRemoteNetworkPolicyBlocksPrivateAndMetadataByDefault(t *testing.T) {
	policy, err := parseRemotePolicy(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200"} {
		if policy.allowedIP(net.ParseIP(value)) {
			t.Fatalf("expected %s to be blocked", value)
		}
	}
}

func TestRemoteCheckRejectsCredentialBearingURLAndUnregisteredActionTarget(t *testing.T) {
	checks := []RemoteCheck{
		{
			ID:             "http-secret",
			Kind:           "http",
			TimeoutSeconds: 1,
			Configuration:  map[string]any{"target": "https://user:pass@example.test/"},
		},
		{
			ID:             "docker-unknown",
			Kind:           "docker",
			TimeoutSeconds: 1,
			Configuration:  map[string]any{"container": "not-registered"},
		},
	}
	results := runRemoteChecks(context.Background(), Config{}, checks)
	for _, result := range results {
		if result["status"] != "failed" {
			t.Fatalf("expected failure, got %#v", result)
		}
	}
}

func TestActionRegistryPersistsAgentRestartCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	config := Config{StateFile: path}
	first := NewActionRegistry(config)
	if first.RestartCount() != 0 {
		t.Fatalf("first start should report zero restarts")
	}
	second := NewActionRegistry(config)
	if second.RestartCount() != 1 {
		t.Fatalf("second start should report one restart")
	}
}

func TestRemoteTCPCheckUsesResolvedAllowlistedAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		connection, _ := listener.Accept()
		if connection != nil {
			_ = connection.Close()
		}
		close(done)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	check := RemoteCheck{
		ID:             "check-tcp",
		Kind:           "tcp",
		TimeoutSeconds: 2,
		Configuration: map[string]any{
			"target":           "127.0.0.1",
			"port":             float64(port),
			"allowed_networks": []any{"127.0.0.1/32"},
		},
	}
	results := runRemoteChecks(context.Background(), Config{}, []RemoteCheck{check})
	if results[0]["status"] != "ok" {
		t.Fatal(fmt.Sprintf("expected TCP success, got %#v", results[0]))
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("test listener did not accept connection")
	}
}
