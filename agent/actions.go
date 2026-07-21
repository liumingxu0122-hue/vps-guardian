package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)
var snapshotHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type ActionResult struct {
	TaskID     string            `json:"task_id"`
	Action     string            `json:"action"`
	Success    bool              `json:"success"`
	DryRun     bool              `json:"dry_run"`
	Before     map[string]string `json:"before"`
	After      map[string]string `json:"after"`
	Message    string            `json:"message"`
	FinishedAt string            `json:"finished_at"`
}

type actionState struct {
	Completed map[string]int64 `json:"completed"`
	LastRun   map[string]int64 `json:"last_run"`
}
type ActionRegistry struct {
	config Config
	mu     sync.Mutex
	state  actionState
}

func NewActionRegistry(config Config) *ActionRegistry {
	r := &ActionRegistry{config: config, state: actionState{map[string]int64{}, map[string]int64{}}}
	if data, err := os.ReadFile(config.StateFile); err == nil {
		_ = json.Unmarshal(data, &r.state)
	}
	return r
}

func (r *ActionRegistry) saveState() error {
	if err := os.MkdirAll(filepath.Dir(r.config.StateFile), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	temporary := r.config.StateFile + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, r.config.StateFile)
}

func (r *ActionRegistry) Execute(ctx context.Context, task Task) ActionResult {
	dryRun := task.Parameters["dry_run"] != "false"
	result := ActionResult{TaskID: task.ID, Action: task.Action, DryRun: dryRun, Before: map[string]string{}, After: map[string]string{}, FinishedAt: time.Now().UTC().Format(time.RFC3339)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, duplicate := r.state.Completed[task.ID]; duplicate {
		result.Success = true
		result.Message = "task was already completed"
		return result
	}
	key := task.Action + ":" + task.Parameters["target"]
	if last := r.state.LastRun[key]; last > 0 && time.Since(time.Unix(last, 0)) < 10*time.Minute {
		result.Message = "action cooldown is active"
		return result
	}
	var err error
	switch task.Action {
	case "restart_container":
		err = r.restartContainer(ctx, task.Parameters["target"], dryRun, &result)
	case "restart_systemd":
		err = r.restartSystemd(ctx, task.Parameters["target"], dryRun, &result)
	case "validate_caddy":
		err = r.validateCaddy(ctx, task.Parameters["target"], &result)
	case "reload_caddy":
		err = r.reloadCaddy(ctx, task.Parameters["target"], dryRun, &result)
	case "local_health_check":
		err = r.localHealthCheck(ctx, task.Parameters["target"], &result)
	case "cleanup_cache":
		err = r.cleanupCache(task.Parameters["target"], dryRun, &result)
	case "rollback_caddy_config":
		err = r.rollbackCaddyConfig(ctx, task.Parameters["target"], task.Parameters["snapshot"], dryRun, &result)
	default:
		err = errors.New("action is not registered")
	}
	result.Success = err == nil
	if err != nil {
		result.Message = err.Error()
	} else if result.Message == "" {
		result.Message = "action completed"
	}
	if !dryRun && err == nil {
		r.state.LastRun[key] = time.Now().Unix()
	}
	r.state.Completed[task.ID] = time.Now().Unix()
	_ = r.saveState()
	return result
}

func runCommand(ctx context.Context, name string, arguments ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput()
	if len(output) > 4096 {
		output = output[:4096]
	}
	if err != nil {
		return string(output), fmt.Errorf("registered command failed: %w", err)
	}
	return string(output), nil
}

func validateIdentifier(value string, allowlist []string) error {
	if !identifierPattern.MatchString(value) || !contains(allowlist, value) {
		return errors.New("target is not allowlisted")
	}
	return nil
}

func (r *ActionRegistry) restartContainer(ctx context.Context, target string, dryRun bool, result *ActionResult) error {
	if err := validateIdentifier(target, r.config.ContainerAllowlist); err != nil {
		return err
	}
	state, _ := runCommand(ctx, "docker", "inspect", "--format", "{{.State.Status}}", target)
	result.Before["state"] = state
	if dryRun {
		result.Message = "would run registered docker restart action"
		return nil
	}
	if _, err := runCommand(ctx, "docker", "restart", "--time", "10", target); err != nil {
		return err
	}
	after, err := runCommand(ctx, "docker", "inspect", "--format", "{{.State.Status}}", target)
	result.After["state"] = after
	return err
}

func (r *ActionRegistry) restartSystemd(ctx context.Context, target string, dryRun bool, result *ActionResult) error {
	if err := validateIdentifier(target, r.config.SystemdAllowlist); err != nil {
		return err
	}
	state, _ := runCommand(ctx, "systemctl", "is-active", target)
	result.Before["state"] = state
	if dryRun {
		result.Message = "would run registered systemd restart action"
		return nil
	}
	if _, err := runCommand(ctx, "systemctl", "restart", target); err != nil {
		return err
	}
	after, err := runCommand(ctx, "systemctl", "is-active", target)
	result.After["state"] = after
	return err
}

func (r *ActionRegistry) validateCaddy(ctx context.Context, target string, result *ActionResult) error {
	if !filepath.IsAbs(target) || !contains(r.config.ConfigAllowlist, target) {
		return errors.New("configuration path is not allowlisted")
	}
	output, err := r.validateCaddyPath(ctx, target)
	result.After["validation"] = output
	return err
}

func (r *ActionRegistry) validateCaddyPath(ctx context.Context, hostPath string) (string, error) {
	if r.config.CaddyContainer == "" {
		return runCommand(ctx, "caddy", "validate", "--config", hostPath)
	}
	containerPath := r.config.CaddyContainerConfig
	if filepath.Base(hostPath) != filepath.Base(r.config.CaddyContainerConfig) {
		containerPath = filepath.Join(filepath.Dir(containerPath), filepath.Base(hostPath))
	}
	return runCommand(
		ctx,
		"docker",
		"exec",
		r.config.CaddyContainer,
		"caddy",
		"validate",
		"--config",
		containerPath,
		"--adapter",
		"caddyfile",
	)
}

func (r *ActionRegistry) performCaddyReload(ctx context.Context) error {
	if r.config.CaddyContainer == "" {
		_, err := runCommand(ctx, "systemctl", "reload", "caddy")
		return err
	}
	_, err := runCommand(
		ctx,
		"docker",
		"exec",
		r.config.CaddyContainer,
		"caddy",
		"reload",
		"--config",
		r.config.CaddyContainerConfig,
		"--adapter",
		"caddyfile",
	)
	return err
}

func (r *ActionRegistry) reloadCaddy(ctx context.Context, target string, dryRun bool, result *ActionResult) error {
	if err := r.validateCaddy(ctx, target, result); err != nil {
		return err
	}
	if dryRun {
		result.Message = "configuration is valid; would reload Caddy"
		return nil
	}
	return r.performCaddyReload(ctx)
}

func (r *ActionRegistry) localHealthCheck(ctx context.Context, target string, result *ActionResult) error {
	if !contains(r.config.LocalHealthURLs, target) {
		return errors.New("health URL is not allowlisted")
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "http" || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost") {
		return errors.New("health URL must use local plain HTTP")
	}
	totalTimeout := time.Duration(r.config.CommandTimeout)
	if totalTimeout <= 0 {
		totalTimeout = 20 * time.Second
	}
	deadline := time.Now().Add(totalTimeout)
	client := &http.Client{Timeout: min(totalTimeout, 2*time.Second)}
	var lastErr error
	for attempt := 1; ; attempt++ {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		response, requestErr := client.Do(request)
		if requestErr == nil {
			result.After["http_status"] = response.Status
			response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 400 {
				result.After["attempts"] = fmt.Sprintf("%d", attempt)
				return nil
			}
			lastErr = fmt.Errorf("local health check returned %d", response.StatusCode)
		} else {
			lastErr = requestErr
		}
		if time.Now().Add(500 * time.Millisecond).After(deadline) {
			result.After["attempts"] = fmt.Sprintf("%d", attempt)
			return lastErr
		}
		select {
		case <-ctx.Done():
			result.After["attempts"] = fmt.Sprintf("%d", attempt)
			return lastErr
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (r *ActionRegistry) cleanupCache(target string, dryRun bool, result *ActionResult) error {
	if !filepath.IsAbs(target) || !contains(r.config.CacheAllowlist, target) {
		return errors.New("cache path is not allowlisted")
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil || resolved != filepath.Clean(target) {
		return errors.New("cache path is missing or resolves through a symbolic link")
	}
	cutoff := time.Now().Add(-time.Duration(r.config.CacheRetention))
	eligible := []string{}
	err = filepath.WalkDir(resolved, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == resolved || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.ModTime().Before(cutoff) {
			if len(eligible) >= 1000 {
				return errors.New("cache cleanup candidate limit exceeded")
			}
			eligible = append(eligible, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	result.Before["eligible_files"] = fmt.Sprintf("%d", len(eligible))
	if dryRun {
		result.Message = "would remove allowlisted expired cache files"
		return nil
	}
	removed := 0
	for _, path := range eligible {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return fmt.Errorf("registered cache cleanup failed: %w", removeErr)
		}
		removed++
	}
	result.After["removed_files"] = fmt.Sprintf("%d", removed)
	return nil
}

func copyFileExclusive(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func readVerifiedSnapshot(root, snapshot, target string) ([]byte, error) {
	candidate := filepath.Join(root, snapshot, filepath.Base(target))
	candidateInfo, err := os.Lstat(candidate)
	if err != nil || !candidateInfo.Mode().IsRegular() || candidateInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("snapshot is not a regular file")
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, errors.New("snapshot file is unavailable")
	}
	relative, err := filepath.Rel(root, resolvedCandidate)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 3 && relative[:3] == ".."+string(os.PathSeparator) {
		return nil, errors.New("snapshot escaped the configured directory")
	}
	manifest := candidate + ".sha256"
	manifestInfo, err := os.Lstat(manifest)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("snapshot hash manifest is unavailable")
	}
	expectedData, err := os.ReadFile(manifest)
	if err != nil {
		return nil, errors.New("snapshot hash manifest is unavailable")
	}
	expectedHash := strings.TrimSpace(string(expectedData))
	if !snapshotHashPattern.MatchString(expectedHash) {
		return nil, errors.New("snapshot hash manifest is invalid")
	}
	candidateData, err := os.ReadFile(resolvedCandidate)
	if err != nil {
		return nil, err
	}
	if sha256String(candidateData) != expectedHash {
		return nil, errors.New("snapshot hash mismatch")
	}
	return candidateData, nil
}

func (r *ActionRegistry) rollbackCaddyConfig(ctx context.Context, target, snapshot string, dryRun bool, result *ActionResult) error {
	if !filepath.IsAbs(target) || !contains(r.config.ConfigAllowlist, target) {
		return errors.New("configuration path is not allowlisted")
	}
	if !identifierPattern.MatchString(snapshot) || !filepath.IsAbs(r.config.SnapshotDirectory) || !filepath.IsAbs(r.config.ActionBackupDirectory) {
		return errors.New("snapshot configuration is invalid")
	}
	root, err := filepath.EvalSymlinks(r.config.SnapshotDirectory)
	if err != nil {
		return errors.New("snapshot directory is unavailable")
	}
	candidateData, err := readVerifiedSnapshot(root, snapshot, target)
	if err != nil {
		return err
	}
	currentInfo, err := os.Lstat(target)
	if err != nil || !currentInfo.Mode().IsRegular() || currentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("current configuration is not a regular file")
	}
	currentData, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	result.Before["config_sha256"] = sha256String(currentData)
	result.After["config_sha256"] = sha256String(candidateData)
	temporary, err := os.CreateTemp(filepath.Dir(target), ".guardian-caddy-candidate-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(currentInfo.Mode().Perm()); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(candidateData); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if _, err := r.validateCaddyPath(ctx, temporaryPath); err != nil {
		return err
	}
	if dryRun {
		result.Message = "snapshot is valid; would atomically restore and reload Caddy"
		return nil
	}
	if err := os.MkdirAll(r.config.ActionBackupDirectory, 0o700); err != nil {
		return err
	}
	backup := filepath.Join(r.config.ActionBackupDirectory, filepath.Base(target)+"."+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := copyFileExclusive(target, backup, 0o600); err != nil {
		return fmt.Errorf("backup current configuration: %w", err)
	}
	result.Before["backup_path"] = backup
	if err := os.Rename(temporaryPath, target); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	if err := r.performCaddyReload(ctx); err == nil {
		return nil
	}
	restore, restoreErr := os.CreateTemp(filepath.Dir(target), ".guardian-caddy-restore-*")
	if restoreErr != nil {
		return errors.New("Caddy reload failed and rollback file could not be created")
	}
	restorePath := restore.Name()
	if _, restoreErr = restore.Write(currentData); restoreErr == nil {
		restoreErr = restore.Chmod(currentInfo.Mode().Perm())
	}
	if closeErr := restore.Close(); restoreErr == nil {
		restoreErr = closeErr
	}
	if restoreErr == nil {
		restoreErr = os.Rename(restorePath, target)
	}
	if restoreErr != nil {
		return errors.New("Caddy reload failed and automatic rollback failed")
	}
	_ = r.performCaddyReload(ctx)
	return errors.New("Caddy reload failed; previous configuration was restored")
}
