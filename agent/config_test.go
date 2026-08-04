package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRequiresHostBindingForPortTraffic(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	values := map[string]any{
		"controller_url":                  "https://agent.example.test",
		"agent_id":                        "agent-1",
		"certificate_file":                filepath.Join(root, "agent.crt"),
		"private_key_file":                filepath.Join(root, "agent.key"),
		"enrollment_https_ca_bundle_file": filepath.Join(root, "enrollment-https-ca-bundle.pem"),
		"signing_key_file":                filepath.Join(root, "signing.pem"),
		"controller_public_key":           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"certificate_fingerprint":         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"port_traffic_enabled":            true,
		"net_helper_socket":               "/run/vps-guardian-net-helper/helper.sock",
	}
	write := func() {
		t.Helper()
		data, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, err := loadConfig(configPath); err == nil ||
		err.Error() != "host_id is required when port traffic is enabled" {
		t.Fatalf("missing local traffic host binding was not rejected: %v", err)
	}
	values["host_id"] = "host-1"
	write()
	if _, err := loadConfig(configPath); err != nil {
		t.Fatalf("host-bound port traffic configuration was rejected: %v", err)
	}
}

func TestLoadConfigMigratesLegacyCAFieldsWithoutAllowingConflicts(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	httpsCA := filepath.Join(root, "controller-ca.crt")
	mtlsCA := filepath.Join(root, "agent-ca.crt")
	values := map[string]any{
		"controller_url":        "https://agent.example.test",
		"agent_id":              "agent-1",
		"certificate_file":      filepath.Join(root, "agent.crt"),
		"private_key_file":      filepath.Join(root, "agent.key"),
		"ca_file":               httpsCA,
		"agent_ca_file":         mtlsCA,
		"signing_key_file":      filepath.Join(root, "signing.pem"),
		"controller_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	write := func() {
		t.Helper()
		data, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.EnrollmentHTTPSCABundleFile != httpsCA || config.AgentMTLSCABundleFile != mtlsCA {
		t.Fatal("legacy CA fields were not migrated into their explicit trust purposes")
	}
	values["enrollment_https_ca_bundle_file"] = filepath.Join(root, "different-ca.pem")
	write()
	if _, err := loadConfig(configPath); err == nil {
		t.Fatal("conflicting legacy and explicit Enrollment HTTPS CA paths were accepted")
	}
}

func TestLoadConfigRequiresPairedAllowlistedCaddyContainerSettings(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	values := map[string]any{
		"controller_url":                  "https://agent.example.test",
		"agent_id":                        "agent-1",
		"certificate_file":                filepath.Join(root, "agent.crt"),
		"private_key_file":                filepath.Join(root, "agent.key"),
		"enrollment_https_ca_bundle_file": filepath.Join(root, "enrollment-https-ca-bundle.pem"),
		"signing_key_file":                filepath.Join(root, "signing.pem"),
		"controller_public_key":           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"certificate_fingerprint":         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"caddy_container":                 "fixture-caddy",
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
		"controller_url":                  "https://agent.example.test:18444",
		"agent_id":                        "agent-1",
		"certificate_file":                filepath.Join(root, "agent.crt"),
		"private_key_file":                filepath.Join(root, "agent.key"),
		"enrollment_https_ca_bundle_file": filepath.Join(root, "enrollment-https-ca-bundle.pem"),
		"signing_key_file":                filepath.Join(root, "signing.pem"),
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
