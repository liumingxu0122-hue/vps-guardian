package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxPolicies     = 64
	tableName       = "vps_guardian_port_traffic"
	statePath       = "/var/lib/vps-guardian-net-helper/policies.json"
	lockPath        = "/run/lock/vps-guardian-net-helper.lock"
	agentConfigPath = "/etc/vps-guardian-agent/config.json"
	tcHandle        = "7a11:"
)

var (
	policyIDPattern  = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	interfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,30}$`)
)

type request struct {
	Operation     string            `json:"operation"`
	DryRun        bool              `json:"dry_run"`
	Policy        map[string]string `json:"policy"`
	Authorization *authorization    `json:"authorization,omitempty"`
}

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

type policy struct {
	ID            string `json:"id"`
	Protocol      string `json:"protocol"`
	Direction     string `json:"direction"`
	PortStart     int    `json:"port_start"`
	PortEnd       int    `json:"port_end"`
	InterfaceName string `json:"interface_name,omitempty"`
	Mode          string `json:"mode"`
	QuotaBytes    int64  `json:"quota_bytes,omitempty"`
	EgressRateBPS int64  `json:"egress_rate_bps,omitempty"`
	Generation    int64  `json:"generation"`
	LifetimeRX    int64  `json:"lifetime_rx"`
	LifetimeTX    int64  `json:"lifetime_tx"`
	LastKernelRX  int64  `json:"last_kernel_rx"`
	LastKernelTX  int64  `json:"last_kernel_tx"`
	PeriodStartRX int64  `json:"period_start_rx"`
	PeriodStartTX int64  `json:"period_start_tx"`
	PeriodStarted int64  `json:"period_started_at"`
	LastResetAt   int64  `json:"last_reset_at,omitempty"`
	NextResetAt   string `json:"next_reset_at,omitempty"`
	ResetPolicy   string `json:"reset_policy"`
}

type state struct {
	Version        int              `json:"version"`
	Policies       []policy         `json:"policies"`
	CompletedNonce map[string]int64 `json:"completed_nonce,omitempty"`
}

type counterTotals struct {
	RX int64
	TX int64
}

func parseInt(value, name string, minimum, maximum int64) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s is outside the permitted range", name)
	}
	return parsed, nil
}

func parsePolicy(values map[string]string, checkInterface bool) (policy, error) {
	if len(values) == 0 || len(values) > 12 {
		return policy{}, errors.New("policy is missing or exceeds field limits")
	}
	id := values["id"]
	if !policyIDPattern.MatchString(id) {
		return policy{}, errors.New("policy id is invalid")
	}
	protocol := values["protocol"]
	if protocol != "tcp" && protocol != "udp" && protocol != "both" {
		return policy{}, errors.New("protocol is invalid")
	}
	direction := values["direction"]
	if direction != "rx" && direction != "tx" && direction != "both" {
		return policy{}, errors.New("direction is invalid")
	}
	mode := values["mode"]
	if mode != "monitor_only" && mode != "enforcing" {
		return policy{}, errors.New("mode is invalid")
	}
	start, err := parseInt(values["port_start"], "port_start", 1, 65535)
	if err != nil {
		return policy{}, err
	}
	end, err := parseInt(values["port_end"], "port_end", start, 65535)
	if err != nil || end-start+1 > 4096 {
		return policy{}, errors.New("port range is invalid")
	}
	quota, err := parseInt(values["quota_bytes"], "quota_bytes", 0, 1<<62)
	if err != nil {
		return policy{}, err
	}
	rate, err := parseInt(values["egress_rate_bps"], "egress_rate_bps", 0, 100_000_000_000)
	if err != nil || (rate > 0 && rate < 8000) {
		return policy{}, errors.New("egress rate is invalid")
	}
	generation, err := parseInt(values["counter_generation"], "counter_generation", 1, 1<<31-1)
	if err != nil {
		return policy{}, err
	}
	if mode == "enforcing" && quota == 0 {
		return policy{}, errors.New("enforcing mode requires a quota")
	}
	if rate > 0 && direction == "rx" {
		return policy{}, errors.New("first-version shaping supports egress only")
	}
	iface := values["interface_name"]
	if iface != "" {
		if !interfacePattern.MatchString(iface) {
			return policy{}, errors.New("interface name is invalid")
		}
		if checkInterface {
			if _, err := net.InterfaceByName(iface); err != nil {
				return policy{}, errors.New("interface does not exist")
			}
		}
	}
	reset := values["reset_policy"]
	var resetObject map[string]any
	if len(reset) > 1024 ||
		json.Unmarshal([]byte(reset), &resetObject) != nil ||
		resetObject == nil {
		return policy{}, errors.New("reset policy is invalid")
	}
	nextReset := values["next_reset_at"]
	if nextReset != "" {
		if len(nextReset) > 40 {
			return policy{}, errors.New("next reset timestamp is invalid")
		}
		if _, err := time.Parse(time.RFC3339, nextReset); err != nil {
			return policy{}, errors.New("next reset timestamp is invalid")
		}
	}
	return policy{
		ID: id, Protocol: protocol, Direction: direction,
		PortStart: int(start), PortEnd: int(end), InterfaceName: iface,
		Mode: mode, QuotaBytes: quota, EgressRateBPS: rate,
		Generation: generation, ResetPolicy: reset, NextResetAt: nextReset,
	}, nil
}

func protocols(value string) []string {
	if value == "both" {
		return []string{"tcp", "udp"}
	}
	return []string{value}
}

func policyKey(id string) string {
	return "vg_" + strings.ReplaceAll(id, "-", "")
}
