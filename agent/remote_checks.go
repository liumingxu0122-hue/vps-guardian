package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type RemoteCheck struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	Configuration  map[string]any `json:"configuration"`
	TimeoutSeconds int            `json:"timeout_seconds"`
}

func remoteString(configuration map[string]any, key string) string {
	value, _ := configuration[key].(string)
	return value
}

func remoteInt(configuration map[string]any, key string, fallback int) int {
	switch value := configuration[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return fallback
	}
}

func remoteStrings(configuration map[string]any, key string) []string {
	values, _ := configuration[key].([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

type remoteNetworkPolicy struct {
	allowed []*net.IPNet
	denied  []*net.IPNet
}

func parseRemotePolicy(configuration map[string]any) (remoteNetworkPolicy, error) {
	policy := remoteNetworkPolicy{}
	for _, item := range remoteStrings(configuration, "allowed_networks") {
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return policy, errors.New("allowed network is invalid")
		}
		policy.allowed = append(policy.allowed, network)
	}
	for _, item := range remoteStrings(configuration, "denied_networks") {
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return policy, errors.New("denied network is invalid")
		}
		policy.denied = append(policy.denied, network)
	}
	return policy, nil
}

func (policy remoteNetworkPolicy) allowedIP(ip net.IP) bool {
	if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("100.100.100.200")) {
		return false
	}
	for _, network := range policy.denied {
		if network.Contains(ip) {
			return false
		}
	}
	if len(policy.allowed) > 0 {
		for _, network := range policy.allowed {
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified()
}

func (policy remoteNetworkPolicy) resolve(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, errors.New("target resolution failed")
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if !policy.allowedIP(address.IP) {
			return nil, errors.New("target address is blocked by network policy")
		}
		result = append(result, address.IP)
	}
	if len(result) == 0 {
		return nil, errors.New("target resolution returned no addresses")
	}
	return result, nil
}

func remoteHTTPCheck(ctx context.Context, check RemoteCheck) (map[string]any, error) {
	target := remoteString(check.Configuration, "target")
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("HTTP target must be a credential-free HTTP(S) URL")
	}
	policy, err := parseRemotePolicy(check.Configuration)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: time.Duration(check.TimeoutSeconds) * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, errors.New("HTTP target address is invalid")
			}
			addresses, resolveErr := policy.resolve(dialContext, host)
			if resolveErr != nil {
				return nil, resolveErr
			}
			return dialer.DialContext(dialContext, network, net.JoinHostPort(addresses[0].String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	redirects := 0
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(check.TimeoutSeconds) * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			redirects++
			if redirects > 3 || request.URL.User != nil || request.URL.RawQuery != "" ||
				request.URL.Fragment != "" ||
				(request.URL.Scheme != "http" && request.URL.Scheme != "https") {
				return errors.New("HTTP redirect is blocked")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("HTTP request is invalid")
	}
	request.Header.Set("User-Agent", "VPS-Guardian-Agent/0.2")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("HTTP check failed: %w", err)
	}
	defer response.Body.Close()
	limit := remoteInt(check.Configuration, "max_response_bytes", 65536)
	if limit < 1024 || limit > 1024*1024 {
		return nil, errors.New("HTTP response limit is invalid")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, errors.New("HTTP response read failed")
	}
	if len(body) > limit {
		return nil, errors.New("HTTP response exceeded the configured size limit")
	}
	expectedStatuses := check.Configuration["expected_statuses"]
	statusOK := response.StatusCode == http.StatusOK
	if values, ok := expectedStatuses.([]any); ok && len(values) > 0 {
		statusOK = false
		for _, value := range values {
			if number, ok := value.(float64); ok && int(number) == response.StatusCode {
				statusOK = true
			}
		}
	}
	if !statusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if expected := remoteString(check.Configuration, "expected_contains"); expected != "" &&
		!strings.Contains(string(body), expected) {
		return nil, errors.New("expected response content missing")
	}
	details := map[string]any{"status": response.StatusCode, "content_length": len(body)}
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		details["tls_expires_at"] = response.TLS.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
		details["tls_hostname_verified"] = true
	}
	return details, nil
}

func remoteTCPCheck(ctx context.Context, check RemoteCheck) (map[string]any, error) {
	host := remoteString(check.Configuration, "target")
	port := remoteInt(check.Configuration, "port", 0)
	if host == "" || port < 1 || port > 65535 {
		return nil, errors.New("TCP target is invalid")
	}
	policy, err := parseRemotePolicy(check.Configuration)
	if err != nil {
		return nil, err
	}
	addresses, err := policy.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(
		ctx, "tcp", net.JoinHostPort(addresses[0].String(), strconv.Itoa(port)),
	)
	if err != nil {
		return nil, errors.New("TCP connection failed")
	}
	defer connection.Close()
	return map[string]any{"peer": connection.RemoteAddr().String()}, nil
}

func remoteSystemdCheck(ctx context.Context, config Config, check RemoteCheck) (map[string]any, error) {
	unit := remoteString(check.Configuration, "unit")
	if err := validateIdentifier(unit, config.SystemdAllowlist); err != nil {
		return nil, err
	}
	output, err := runCommand(
		ctx,
		"systemctl",
		"show",
		unit,
		"--property=ActiveState,SubState,ActiveEnterTimestampMonotonic,ExecMainStatus",
	)
	if err != nil {
		return nil, err
	}
	details := map[string]any{}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			details[strings.ToLower(parts[0])] = parts[1]
		}
	}
	if details["activestate"] != "active" {
		return details, errors.New("systemd unit is not active")
	}
	return details, nil
}

func remoteDockerCheck(ctx context.Context, config Config, check RemoteCheck) (map[string]any, error) {
	container := remoteString(check.Configuration, "container")
	if err := validateIdentifier(container, config.ContainerAllowlist); err != nil {
		return nil, err
	}
	output, err := runCommand(
		ctx,
		"docker",
		"inspect",
		"--format",
		"{{json .State}}|{{.Config.Image}}|{{.Image}}|{{.RestartCount}}",
		container,
	)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(strings.TrimSpace(output), "|", 4)
	if len(parts) != 4 {
		return nil, errors.New("Docker inspection result is invalid")
	}
	state := map[string]any{}
	if err := json.Unmarshal([]byte(parts[0]), &state); err != nil {
		return nil, errors.New("Docker state is invalid")
	}
	details := map[string]any{
		"state":         state,
		"image":         parts[1],
		"image_id":      parts[2],
		"restart_count": parts[3],
	}
	status, _ := state["Status"].(string)
	healthy := status == "running"
	if health, ok := state["Health"].(map[string]any); ok {
		healthy = healthy && health["Status"] == "healthy"
	}
	if !healthy {
		return details, errors.New("Docker container is not running and healthy")
	}
	return details, nil
}

func runRemoteCheck(ctx context.Context, config Config, check RemoteCheck) (details map[string]any, err error) {
	switch check.Kind {
	case "http", "https":
		return remoteHTTPCheck(ctx, check)
	case "tcp":
		return remoteTCPCheck(ctx, check)
	case "systemd":
		return remoteSystemdCheck(ctx, config, check)
	case "docker":
		return remoteDockerCheck(ctx, config, check)
	case "icmp":
		target := remoteString(check.Configuration, "target")
		policy, policyErr := parseRemotePolicy(check.Configuration)
		if policyErr != nil {
			return nil, policyErr
		}
		addresses, resolveErr := policy.resolve(ctx, target)
		if resolveErr != nil {
			return nil, resolveErr
		}
		output, commandErr := exec.CommandContext(ctx, "ping", "-c", "1", addresses[0].String()).CombinedOutput()
		if commandErr != nil {
			if errors.Is(commandErr, exec.ErrNotFound) {
				return map[string]any{"unsupported": true}, errors.New("ICMP probe is unsupported")
			}
			return nil, errors.New("ICMP probe failed")
		}
		return map[string]any{"reply_bytes": len(output)}, nil
	default:
		return nil, errors.New("check kind is unsupported")
	}
}

func runRemoteChecks(ctx context.Context, config Config, checks []RemoteCheck) []map[string]any {
	if len(checks) > 100 {
		checks = checks[:100]
	}
	results := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		started := time.Now()
		result := map[string]any{
			"kind":     "guardian_check_result",
			"check_id": check.ID,
			"status":   "failed",
		}
		if !identifierPattern.MatchString(check.ID) {
			result["message"] = "check identity is invalid"
			results = append(results, result)
			continue
		}
		if check.TimeoutSeconds < 1 || check.TimeoutSeconds > 30 {
			check.TimeoutSeconds = 5
		}
		checkContext, cancel := context.WithTimeout(ctx, time.Duration(check.TimeoutSeconds)*time.Second)
		details, err := runRemoteCheck(checkContext, config, check)
		cancel()
		result["latency_ms"] = float64(time.Since(started).Microseconds()) / 1000
		if details != nil {
			result["details"] = details
		}
		if err == nil {
			result["status"] = "ok"
		} else if details != nil && details["unsupported"] == true {
			result["status"] = "unsupported"
			result["message"] = "probe is unsupported"
		} else {
			result["message"] = err.Error()
		}
		results = append(results, result)
	}
	return results
}
