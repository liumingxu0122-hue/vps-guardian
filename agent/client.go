package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type HeartbeatResponse struct {
	Accepted        bool          `json:"accepted"`
	ServerTime      string        `json:"server_time"`
	IdentityState   string        `json:"identity_state"`
	IdentityVersion int           `json:"identity_version"`
	Tasks           []Task        `json:"tasks"`
	Checks          []RemoteCheck `json:"checks"`
}
type ControllerClient struct {
	config      Config
	httpClient  *http.Client
	signingKey  ed25519.PrivateKey
	serverKey   ed25519.PublicKey
	certificate *x509.Certificate
}

func NewControllerClient(config Config) (*ControllerClient, error) {
	certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	if len(certificate.Certificate) != 1 {
		return nil, errors.New("Agent certificate file must contain exactly one certificate")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse Agent certificate: %w", err)
	}
	config.CertificateFP = certificateFingerprint(leaf)
	caData, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, errors.New("CA file did not contain a certificate")
	}
	signingKey, err := loadEd25519PrivateKey(config.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	serverKey, err := decodeControllerPublicKey(config.ControllerPublicKey)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: caPool, Certificates: []tls.Certificate{certificate}}}
	return &ControllerClient{
		config:      config,
		httpClient:  &http.Client{Transport: transport, Timeout: time.Duration(config.CommandTimeout)},
		signingKey:  signingKey,
		serverKey:   serverKey,
		certificate: leaf,
	}, nil
}

func (c *ControllerClient) CertificateExpiresWithin(now time.Time, window time.Duration) bool {
	return !c.certificate.NotAfter.After(now.Add(window))
}

func (c *ControllerClient) Heartbeat(ctx context.Context, snapshot Snapshot) (HeartbeatResponse, error) {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return HeartbeatResponse{}, err
	}
	headers, err := signHeartbeat(c.config.AgentID, body, c.signingKey)
	if err != nil {
		return HeartbeatResponse{}, err
	}
	endpoint := strings.TrimRight(c.config.ControllerURL, "/") + "/api/v1/agents/" + c.config.AgentID + "/heartbeat"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return HeartbeatResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Client-Cert-Fingerprint", c.config.CertificateFP)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return HeartbeatResponse{}, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return HeartbeatResponse{}, err
	}
	return decodeHeartbeatResponse(response.StatusCode, responseBody)
}

func decodeHeartbeatResponse(statusCode int, responseBody []byte) (HeartbeatResponse, error) {
	if statusCode != http.StatusAccepted && statusCode != http.StatusTooEarly {
		return HeartbeatResponse{}, fmt.Errorf("controller returned status %d", statusCode)
	}
	var heartbeat HeartbeatResponse
	if err := json.Unmarshal(responseBody, &heartbeat); err != nil {
		return HeartbeatResponse{}, err
	}
	if statusCode == http.StatusTooEarly {
		if heartbeat.Accepted || heartbeat.IdentityState != "pending" {
			return HeartbeatResponse{}, errors.New("controller returned an invalid pending identity response")
		}
		return heartbeat, nil
	}
	if !heartbeat.Accepted {
		return HeartbeatResponse{}, errors.New("controller did not accept the heartbeat")
	}
	return heartbeat, nil
}
