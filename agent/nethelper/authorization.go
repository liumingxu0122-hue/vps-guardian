package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"
)

type signedAuthorization struct {
	ID           string            `json:"id"`
	Action       string            `json:"action"`
	Parameters   map[string]string `json:"parameters"`
	Nonce        string            `json:"nonce"`
	ExpiresAt    int64             `json:"expires_at"`
	ApprovalID   string            `json:"approval_id"`
	RequesterID  string            `json:"requester_id"`
	ApproverID   string            `json:"approver_id"`
	TargetHostID string            `json:"target_host_id"`
}

func loadControllerTrust(path string) (ed25519.PublicKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 {
		return nil, "", errors.New("root-owned Agent configuration is unavailable")
	}
	var config struct {
		ControllerPublicKey string `json:"controller_public_key"`
		HostID              string `json:"host_id"`
	}
	if json.Unmarshal(data, &config) != nil {
		return nil, "", errors.New("root-owned Agent configuration is invalid")
	}
	decoded, err := base64.StdEncoding.DecodeString(config.ControllerPublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, "", errors.New("Controller public key is invalid")
	}
	if config.HostID == "" {
		return nil, "", errors.New("local host identity is unavailable")
	}
	return ed25519.PublicKey(decoded), config.HostID, nil
}

func helperAction(operation string) string {
	return map[string]string{
		"apply":  "port_traffic_apply",
		"remove": "port_traffic_remove",
		"reset":  "port_traffic_reset",
	}[operation]
}

func parameterMatches(request request, key, policyKey string) bool {
	if request.Authorization == nil {
		return false
	}
	return request.Authorization.Parameters[key] == request.Policy[policyKey]
}

func verifyAuthorization(
	request request,
	publicKey ed25519.PublicKey,
	expectedHostID string,
	completed map[string]int64,
	now time.Time,
) error {
	auth := request.Authorization
	if auth == nil || auth.Action != helperAction(request.Operation) {
		return errors.New("signed authorization is required")
	}
	if auth.ID == "" || len(auth.Nonce) < 16 || auth.TargetHostID == "" {
		return errors.New("signed authorization identity is invalid")
	}
	if auth.TargetHostID != expectedHostID {
		return errors.New("signed authorization targets another host")
	}
	if auth.ExpiresAt < now.Unix() || auth.ExpiresAt > now.Add(15*time.Minute).Unix() {
		return errors.New("signed authorization expiry is invalid")
	}
	if _, replayed := completed[auth.Nonce]; replayed {
		return errors.New("signed authorization nonce was already used")
	}
	for taskKey, requestKey := range map[string]string{
		"policy_id":          "id",
		"protocol":           "protocol",
		"direction":          "direction",
		"port_start":         "port_start",
		"port_end":           "port_end",
		"interface_name":     "interface_name",
		"mode":               "mode",
		"quota_bytes":        "quota_bytes",
		"egress_rate_bps":    "egress_rate_bps",
		"counter_generation": "counter_generation",
		"reset_policy":       "reset_policy",
		"next_reset_at":      "next_reset_at",
	} {
		if !parameterMatches(request, taskKey, requestKey) {
			return errors.New("signed authorization parameters do not match")
		}
	}
	expectedDryRun := "false"
	if request.DryRun {
		expectedDryRun = "true"
	}
	if auth.Parameters["dry_run"] != expectedDryRun {
		return errors.New("signed authorization dry-run state does not match")
	}
	risky := request.Operation == "reset" ||
		request.Policy["mode"] == "enforcing" ||
		request.Policy["egress_rate_bps"] != "0"
	if risky && (auth.ApprovalID == "" ||
		auth.RequesterID == "" ||
		auth.ApproverID == "" ||
		auth.RequesterID == auth.ApproverID) {
		return errors.New("risky helper operation lacks independent approval")
	}
	payload, err := json.Marshal(signedAuthorization{
		ID: auth.ID, Action: auth.Action, Parameters: auth.Parameters,
		Nonce: auth.Nonce, ExpiresAt: auth.ExpiresAt,
		ApprovalID: auth.ApprovalID, RequesterID: auth.RequesterID,
		ApproverID: auth.ApproverID, TargetHostID: auth.TargetHostID,
	})
	if err != nil {
		return errors.New("signed authorization payload is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(auth.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("signed authorization signature is invalid")
	}
	return nil
}

func consumeNonce(current *state, nonce string, expiresAt int64, now time.Time) {
	oldestNonce := ""
	oldestExpiry := int64(1<<63 - 1)
	for item, expiry := range current.CompletedNonce {
		if expiry < now.Unix() {
			delete(current.CompletedNonce, item)
			continue
		}
		if expiry < oldestExpiry {
			oldestNonce, oldestExpiry = item, expiry
		}
	}
	if len(current.CompletedNonce) >= 4096 && oldestNonce != "" {
		delete(current.CompletedNonce, oldestNonce)
	}
	current.CompletedNonce[nonce] = expiresAt
}
