package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"time"
)

type Snapshot struct {
	CollectedAt string            `json:"collected_at"`
	Version     string            `json:"version"`
	Metrics     map[string]any    `json:"metrics"`
	Services    []map[string]any  `json:"services"`
	Events      []json.RawMessage `json:"events"`
}

func collectCommand(ctx context.Context, name string, arguments ...string) string {
	output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput()
	if err != nil {
		return ""
	}
	if len(output) > 64*1024 {
		output = output[:64*1024]
	}
	return string(output)
}

func collectServices(ctx context.Context, config Config) []map[string]any {
	services := []map[string]any{}
	commands := []struct {
		kind, name string
		args       []string
	}{
		{"systemd_failed", "systemctl", []string{"list-units", "--type=service", "--state=failed", "--no-pager", "--plain"}},
		{"docker", "docker", []string{"ps", "-a", "--format", "{{json .}}"}},
		{"compose", "docker", []string{"compose", "ls", "--format", "json"}},
		{"listening_ports", "ss", []string{"-lntupH"}},
		{"journal_errors", "journalctl", []string{"-p", "err", "--since", "-10min", "--no-pager", "-n", "100"}},
	}
	for _, command := range commands {
		if output := collectCommand(ctx, command.name, command.args...); output != "" {
			services = append(services, map[string]any{"kind": command.kind, "summary": output})
		}
	}
	for _, container := range config.ContainerAllowlist {
		output, err := runCommand(ctx, "docker", "logs", "--tail", "100", "--since", "10m", container)
		if output != "" {
			services = append(services, map[string]any{
				"kind": "container_logs", "container": container, "summary": output, "read_ok": err == nil,
			})
		}
	}
	if config.CaddyContainer != "" && len(config.ConfigAllowlist) == 1 {
		output, err := runCommand(
			ctx, "docker", "exec", config.CaddyContainer, "caddy", "validate",
			"--config", config.CaddyContainerConfig, "--adapter", "caddyfile",
		)
		services = append(services, map[string]any{
			"kind": "config_validation", "container": config.CaddyContainer,
			"config_path": config.ConfigAllowlist[0], "healthy": err == nil, "summary": output,
		})
	}
	return services
}

func collectSnapshot(config Config, queue *DiskQueue) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.CommandTimeout))
	defer cancel()
	metrics, err := collectHostMetrics(config.DiskPath)
	if err != nil && !errors.Is(err, errUnsupportedPlatform) {
		return Snapshot{}, err
	}
	events, err := queue.Snapshot(100)
	if err != nil {
		return Snapshot{}, err
	}
	queueDepth, err := queue.Depth()
	if err != nil {
		return Snapshot{}, err
	}
	metrics["offline_queue_depth"] = queueDepth
	metrics["probes"] = collectProbes(ctx, config)
	return Snapshot{time.Now().UTC().Format(time.RFC3339Nano), "0.1.0", metrics, collectServices(ctx, config), events}, nil
}
