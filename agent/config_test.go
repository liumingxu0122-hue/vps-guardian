package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRequiresPairedAllowlistedCaddyContainerSettings(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	values := map[string]any{
		"controller_url":          "https://agent.example.test",
		"agent_id":                "agent-1",
		"certificate_file":        filepath.Join(root, "agent.crt"),
		"private_key_file":        filepath.Join(root, "agent.key"),
		"ca_file":                 filepath.Join(root, "controller-ca.crt"),
		"signing_key_file":        filepath.Join(root, "signing.pem"),
		"controller_public_key":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"certificate_fingerprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"caddy_container":         "fixture-caddy",
	}
	base, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, base, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(configPath); err == nil || err.Error() != "caddy_container and caddy_container_config must be set together" {
		t.Fatalf("incomplete Caddy container settings were not rejected: %v", err)
	}

	containerConfig := filepath.Join(root, "container-Caddyfile")
	values["container_allowlist"] = []string{"fixture-caddy"}
	values["caddy_container_config"] = containerConfig
	complete, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, complete, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.CaddyContainerConfig != containerConfig {
		t.Fatalf("unexpected Caddy container config: %s", config.CaddyContainerConfig)
	}
}

func TestLoadConfigValidatesProbeTargets(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	values := map[string]any{
		"controller_url":   "https://agent.example.test:18444",
		"agent_id":         "agent-1",
		"certificate_file": filepath.Join(root, "agent.crt"),
		"private_key_file": filepath.Join(root, "agent.key"),
		"ca_file":          filepath.Join(root, "controller-ca.crt"),
		"signing_key_file": filepath.Join(root, "signing.pem"),
		"probe_targets": []map[string]any{{
			"name": "controller", "tcp_address": "agent.example.test:18444",
			"http_url": "https://agent.example.test:18444/health",
		}},
	}
	write := func() error {
		data, err := json.Marshal(values)
		if err != nil {
			return err
		}
		return os.WriteFile(configPath, data, 0o600)
	}
	if err := write(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(configPath); err != nil {
		t.Fatalf("valid probe target was rejected: %v", err)
	}
	values["probe_targets"] = []map[string]any{{
		"name": "controller", "tcp_address": "missing-port",
	}}
	if err := write(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(configPath); err == nil {
		t.Fatal("probe address without a port was accepted")
	}
	values["probe_targets"] = []map[string]any{{
		"name": "controller", "http_url": "file:///etc/passwd",
	}}
	if err := write(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(configPath); err == nil {
		t.Fatal("non-HTTP probe URL was accepted")
	}
}
