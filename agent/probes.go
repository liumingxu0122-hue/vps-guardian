package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func elapsedMilliseconds(started time.Time) int64 {
	return time.Since(started).Milliseconds()
}

func collectProbes(ctx context.Context, config Config) []map[string]any {
	results := make([]map[string]any, 0, len(config.ProbeTargets))
	for _, target := range config.ProbeTargets {
		result := map[string]any{"name": target.Name}
		if target.FailureClass != "" {
			result["failure_class"] = target.FailureClass
		}
		if target.DNSName != "" {
			started := time.Now()
			addresses, err := net.DefaultResolver.LookupHost(ctx, target.DNSName)
			result["dns_ok"] = err == nil && len(addresses) > 0
			result["dns_addresses"] = addresses
			result["dns_latency_ms"] = elapsedMilliseconds(started)
		}
		if target.TCPAddress != "" {
			started := time.Now()
			connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(
				ctx, "tcp", target.TCPAddress,
			)
			result["tcp_ok"] = err == nil
			result["tcp_latency_ms"] = elapsedMilliseconds(started)
			if connection != nil {
				_ = connection.Close()
			}
		}
		if target.TLSAddress != "" {
			probeTLS(ctx, config, target, result)
		}
		if target.HTTPURL != "" {
			probeHTTP(ctx, target, result)
		}
		if target.ICMPAddress != "" {
			started := time.Now()
			command := exec.CommandContext(ctx, "ping", "-n", "-c", "1", "-W", "2", target.ICMPAddress)
			result["icmp_ok"] = command.Run() == nil
			result["icmp_latency_ms"] = elapsedMilliseconds(started)
		}
		results = append(results, result)
	}
	return results
}

func probeTLS(ctx context.Context, config Config, target ProbeTarget, result map[string]any) {
	started := time.Now()
	certificate, certErr := tls.LoadX509KeyPair(config.CertificateFile, config.PrivateKeyFile)
	caData, caErr := os.ReadFile(config.CAFile)
	roots := x509.NewCertPool()
	if certErr != nil || caErr != nil || !roots.AppendCertsFromPEM(caData) {
		result["tls_ok"] = false
		return
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots,
			Certificates: []tls.Certificate{certificate},
			ServerName:   target.TLSServerName,
		},
	}
	connection, err := dialer.DialContext(ctx, "tcp", target.TLSAddress)
	result["tls_ok"] = err == nil
	result["tls_latency_ms"] = elapsedMilliseconds(started)
	if err == nil {
		state := connection.(*tls.Conn).ConnectionState()
		result["tls_version"] = tls.VersionName(state.Version)
		_ = connection.Close()
	}
}

func probeHTTP(ctx context.Context, target ProbeTarget, result map[string]any) {
	started := time.Now()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.HTTPURL, nil)
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	result["http_ok"] = err == nil && response.StatusCode >= 200 && response.StatusCode < 400
	result["http_latency_ms"] = elapsedMilliseconds(started)
	if err != nil {
		return
	}
	defer response.Body.Close()
	result["http_status"] = response.StatusCode
	if target.ExpectJSON {
		var payload any
		result["json_ok"] = json.NewDecoder(response.Body).Decode(&payload) == nil
	}
}
