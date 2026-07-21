package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type ProbeTarget struct {
	Name          string `json:"name"`
	DNSName       string `json:"dns_name"`
	TCPAddress    string `json:"tcp_address"`
	TLSAddress    string `json:"tls_address"`
	TLSServerName string `json:"tls_server_name"`
	HTTPURL       string `json:"http_url"`
	ExpectJSON    bool   `json:"expect_json"`
	ICMPAddress   string `json:"icmp_address"`
	FailureClass  string `json:"failure_class"`
}

type Config struct {
	ControllerURL         string        `json:"controller_url"`
	AgentID               string        `json:"agent_id"`
	CertificateFile       string        `json:"certificate_file"`
	PrivateKeyFile        string        `json:"private_key_file"`
	CAFile                string        `json:"ca_file"`
	SigningKeyFile        string        `json:"signing_key_file"`
	ControllerPublicKey   string        `json:"controller_public_key"`
	CertificateFP         string        `json:"certificate_fingerprint"`
	QueueFile             string        `json:"queue_file"`
	StateFile             string        `json:"state_file"`
	HeartbeatInterval     Duration      `json:"heartbeat_interval"`
	CommandTimeout        Duration      `json:"command_timeout"`
	MaxQueueBytes         int64         `json:"max_queue_bytes"`
	DiskPath              string        `json:"disk_path"`
	SystemdAllowlist      []string      `json:"systemd_allowlist"`
	ContainerAllowlist    []string      `json:"container_allowlist"`
	ConfigAllowlist       []string      `json:"config_allowlist"`
	CacheAllowlist        []string      `json:"cache_allowlist"`
	CacheRetention        Duration      `json:"cache_retention"`
	CaddyContainer        string        `json:"caddy_container"`
	CaddyContainerConfig  string        `json:"caddy_container_config"`
	SnapshotDirectory     string        `json:"snapshot_directory"`
	ActionBackupDirectory string        `json:"action_backup_directory"`
	LocalHealthURLs       []string      `json:"local_health_urls"`
	ProbeTargets          []ProbeTarget `json:"probe_targets"`
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	decoder := json.NewDecoder(bytesReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if config.ControllerURL == "" || config.AgentID == "" {
		return Config{}, errors.New("controller_url and agent_id are required")
	}
	for _, keyPath := range []string{
		config.CertificateFile, config.PrivateKeyFile, config.CAFile, config.SigningKeyFile,
	} {
		if !filepath.IsAbs(keyPath) {
			return Config{}, fmt.Errorf("security-sensitive path must be absolute: %s", keyPath)
		}
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = Duration(30 * time.Second)
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = Duration(20 * time.Second)
	}
	if config.MaxQueueBytes == 0 {
		config.MaxQueueBytes = 5 * 1024 * 1024
	}
	if config.DiskPath == "" {
		config.DiskPath = "/"
		if os.PathSeparator == '\\' {
			config.DiskPath = filepath.VolumeName(os.TempDir()) + string(os.PathSeparator)
		}
	}
	if !filepath.IsAbs(config.DiskPath) {
		return Config{}, errors.New("disk_path must be absolute")
	}
	if config.CacheRetention == 0 {
		config.CacheRetention = Duration(24 * time.Hour)
	}
	for _, directory := range []string{config.SnapshotDirectory, config.ActionBackupDirectory} {
		if directory != "" && !filepath.IsAbs(directory) {
			return Config{}, fmt.Errorf("action directory must be absolute: %s", directory)
		}
	}
	if (config.CaddyContainer == "") != (config.CaddyContainerConfig == "") {
		return Config{}, errors.New("caddy_container and caddy_container_config must be set together")
	}
	if config.CaddyContainer != "" {
		if err := validateIdentifier(config.CaddyContainer, config.ContainerAllowlist); err != nil {
			return Config{}, fmt.Errorf("invalid Caddy container: %w", err)
		}
		if !filepath.IsAbs(config.CaddyContainerConfig) {
			return Config{}, errors.New("caddy_container_config must be absolute")
		}
	}
	for _, target := range config.ProbeTargets {
		if !identifierPattern.MatchString(target.Name) {
			return Config{}, fmt.Errorf("invalid probe target name: %s", target.Name)
		}
		if target.FailureClass != "" && target.FailureClass != "database_corruption" {
			return Config{}, fmt.Errorf("invalid probe failure class: %s", target.FailureClass)
		}
		for _, address := range []string{target.TCPAddress, target.TLSAddress} {
			if address == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(address); err != nil {
				return Config{}, fmt.Errorf("invalid probe address: %s", address)
			}
		}
		if target.HTTPURL != "" {
			parsed, err := url.Parse(target.HTTPURL)
			if err != nil || parsed.Host == "" ||
				(parsed.Scheme != "http" && parsed.Scheme != "https") {
				return Config{}, fmt.Errorf("invalid probe HTTP URL: %s", target.HTTPURL)
			}
		}
	}
	return config, nil
}
