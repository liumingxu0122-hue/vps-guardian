// Command sign-port-task creates only synthetic authorization for the isolated
// network-namespace test. It is not built or installed with VPS Guardian.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

type authorization struct {
	ID           string            `json:"id"`
	Action       string            `json:"action"`
	Parameters   map[string]string `json:"parameters"`
	Nonce        string            `json:"nonce"`
	ExpiresAt    int64             `json:"expires_at"`
	Signature    string            `json:"signature"`
	ApprovalID   string            `json:"approval_id"`
	RequesterID  string            `json:"requester_id"`
	ApproverID   string            `json:"approver_id"`
	TargetHostID string            `json:"target_host_id"`
}

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

func main() {
	keyPath := flag.String("key", "", "ephemeral test private key path")
	configPath := flag.String("config", "", "ephemeral helper config path")
	operation := flag.String("operation", "apply", "apply, remove, or reset")
	id := flag.String("id", "", "synthetic policy UUID")
	protocol := flag.String("protocol", "tcp", "tcp, udp, or both")
	port := flag.String("port", "443", "test port")
	endPort := flag.String("end-port", "", "optional test range end")
	direction := flag.String("direction", "both", "rx, tx, or both")
	mode := flag.String("mode", "monitor_only", "monitor_only or enforcing")
	quota := flag.String("quota", "10485760", "test quota bytes")
	rate := flag.String("rate", "0", "test egress rate")
	nextReset := flag.String("next-reset-at", "", "optional synthetic next reset")
	flag.Parse()
	if *keyPath == "" || *configPath == "" || *id == "" {
		panic("key, config, and id are required")
	}
	var private ed25519.PrivateKey
	if data, err := os.ReadFile(*keyPath); err == nil {
		private = ed25519.PrivateKey(data)
	} else {
		public, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		private = generated
		if err := os.WriteFile(*keyPath, private, 0o600); err != nil {
			panic(err)
		}
		config, _ := json.Marshal(map[string]string{
			"controller_public_key": base64.StdEncoding.EncodeToString(public),
			"host_id":               "test-host",
		})
		if err := os.WriteFile(*configPath, config, 0o600); err != nil {
			panic(err)
		}
	}
	action := map[string]string{
		"apply": "port_traffic_apply", "remove": "port_traffic_remove",
		"reset": "port_traffic_reset",
	}[*operation]
	if action == "" {
		panic("operation is invalid")
	}
	if *endPort == "" {
		*endPort = *port
	}
	policy := map[string]string{
		"id": *id, "protocol": *protocol, "direction": *direction,
		"port_start": *port, "port_end": *endPort, "interface_name": "vg0",
		"mode": *mode, "quota_bytes": *quota,
		"egress_rate_bps": *rate, "counter_generation": "1",
		"reset_policy": `{"type":"manual"}`, "next_reset_at": *nextReset,
	}
	parameters := map[string]string{
		"policy_id": *id, "protocol": *protocol, "direction": *direction,
		"port_start": *port, "port_end": *endPort, "interface_name": "vg0",
		"mode": *mode, "quota_bytes": *quota,
		"egress_rate_bps": *rate, "counter_generation": "1",
		"reset_policy": `{"type":"manual"}`, "next_reset_at": *nextReset,
		"dry_run": "false",
	}
	now := time.Now()
	auth := authorization{
		ID: fmt.Sprintf("task-%d", now.UnixNano()), Action: action,
		Parameters: parameters, Nonce: fmt.Sprintf("nonce-%d", now.UnixNano()),
		ExpiresAt: now.Add(5 * time.Minute).Unix(), ApprovalID: "test-approval",
		RequesterID: "test-requester", ApproverID: "test-approver",
		TargetHostID: "test-host",
	}
	payload, _ := json.Marshal(signedAuthorization{
		ID: auth.ID, Action: auth.Action, Parameters: auth.Parameters,
		Nonce: auth.Nonce, ExpiresAt: auth.ExpiresAt, ApprovalID: auth.ApprovalID,
		RequesterID: auth.RequesterID, ApproverID: auth.ApproverID,
		TargetHostID: auth.TargetHostID,
	})
	auth.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	request := map[string]any{
		"operation": *operation, "dry_run": false,
		"policy": policy, "authorization": auth,
	}
	if err := json.NewEncoder(os.Stdout).Encode(request); err != nil {
		panic(err)
	}
}
