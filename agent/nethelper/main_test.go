package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	table    bool
	counters map[string]int64
	scripts  [][]byte
	failNFT  bool
}

func (fake *fakeRunner) run(
	_ context.Context,
	name string,
	arguments []string,
	input []byte,
) ([]byte, error) {
	joined := strings.Join(arguments, " ")
	if name == "nft" && joined == "list table inet "+tableName {
		if fake.table {
			return []byte("table"), nil
		}
		return nil, errors.New("missing")
	}
	if name == "nft" && joined == "-j list ruleset" {
		items := []map[string]any{}
		for counter, value := range fake.counters {
			items = append(items, map[string]any{
				"counter": map[string]any{
					"family": "inet", "table": tableName, "name": counter,
					"bytes": value, "packets": 1,
				},
			})
		}
		return json.Marshal(map[string]any{"nftables": items})
	}
	if name == "nft" && joined == "-f -" {
		fake.scripts = append(fake.scripts, append([]byte(nil), input...))
		if fake.failNFT {
			return nil, errors.New("nft failed")
		}
		if bytes.Contains(input, []byte("delete table inet "+tableName)) &&
			!bytes.Contains(input, []byte("add table inet "+tableName)) {
			fake.table = false
			fake.counters = map[string]int64{}
			return nil, nil
		}
		fake.table = true
		fake.counters = map[string]int64{}
		for _, line := range strings.Split(string(input), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 5 && fields[0] == "add" && fields[1] == "counter" {
				fake.counters[fields[4]] = 0
			}
		}
		return nil, nil
	}
	return []byte("[]"), nil
}

func testKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return public, private
}

func writeAuthConfig(t *testing.T, directory string, public ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(directory, "agent-config.json")
	data, _ := json.Marshal(map[string]string{
		"controller_public_key": base64.StdEncoding.EncodeToString(public),
		"host_id":               "host",
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func policyRequest(id, operation string, private ed25519.PrivateKey) string {
	return policyRequestWithDryRun(id, operation, private, false)
}

func policyRequestWithDryRun(
	id, operation string,
	private ed25519.PrivateKey,
	dryRun bool,
) string {
	policy := map[string]string{
		"id": id, "protocol": "tcp", "direction": "both",
		"port_start": "443", "port_end": "443", "interface_name": "",
		"mode": "monitor_only", "quota_bytes": "1000", "egress_rate_bps": "0",
		"counter_generation": "1", "reset_policy": `{"type":"manual"}`,
		"next_reset_at": "",
	}
	parameters := map[string]string{
		"policy_id": id, "protocol": "tcp", "direction": "both",
		"port_start": "443", "port_end": "443", "interface_name": "",
		"mode": "monitor_only", "quota_bytes": "1000", "egress_rate_bps": "0",
		"counter_generation": "1", "reset_policy": `{"type":"manual"}`,
		"next_reset_at": "",
		"dry_run":       fmt.Sprintf("%t", dryRun),
	}
	auth := authorization{
		ID: "task-" + id, Action: helperAction(operation), Parameters: parameters,
		Nonce: "nonce-" + id + "-" + operation, ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		ApprovalID: "approval", RequesterID: "requester", ApproverID: "approver",
		TargetHostID: "host",
	}
	payload, _ := json.Marshal(signedAuthorization{
		ID: auth.ID, Action: auth.Action, Parameters: auth.Parameters,
		Nonce: auth.Nonce, ExpiresAt: auth.ExpiresAt, ApprovalID: auth.ApprovalID,
		RequesterID: auth.RequesterID, ApproverID: auth.ApproverID,
		TargetHostID: auth.TargetHostID,
	})
	auth.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	encoded, _ := json.Marshal(request{
		Operation: operation, DryRun: dryRun, Policy: policy, Authorization: &auth,
	})
	return string(encoded)
}

func TestDryRunConsumesNonceWithoutChangingPolicyOrNetworkState(t *testing.T) {
	directory := t.TempDir()
	stateFile := filepath.Join(directory, "state.json")
	lockFile := filepath.Join(directory, "helper.lock")
	fake := &fakeRunner{counters: map[string]int64{}}
	public, private := testKeys()
	configFile := writeAuthConfig(t, directory, public)
	var output bytes.Buffer

	err := execute(
		strings.NewReader(
			policyRequestWithDryRun(
				"2d3880fe-23f0-4bd3-bca2-1eea349b2e2c",
				"apply",
				private,
				true,
			),
		),
		&output,
		fake,
		stateFile,
		lockFile,
		configFile,
	)

	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	current, loadErr := loadState(stateFile)
	if loadErr != nil || len(current.Policies) != 0 || len(current.CompletedNonce) != 1 {
		t.Fatalf("dry-run changed policy state: %#v, %v", current, loadErr)
	}
	if len(fake.scripts) != 0 || fake.table {
		t.Fatal("dry-run changed network state")
	}
}

func TestSignedAuthorizationMustTargetTheLocalHost(t *testing.T) {
	directory := t.TempDir()
	stateFile := filepath.Join(directory, "state.json")
	lockFile := filepath.Join(directory, "helper.lock")
	fake := &fakeRunner{counters: map[string]int64{}}
	public, private := testKeys()
	configFile := filepath.Join(directory, "agent-config.json")
	config, _ := json.Marshal(map[string]string{
		"controller_public_key": base64.StdEncoding.EncodeToString(public),
		"host_id":               "different-host",
	})
	if err := os.WriteFile(configFile, config, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := execute(
		strings.NewReader(
			policyRequest("2d3880fe-23f0-4bd3-bca2-1eea349b2e2c", "apply", private),
		),
		&output,
		fake,
		stateFile,
		lockFile,
		configFile,
	)
	if err == nil || err.Error() != "signed authorization targets another host" {
		t.Fatalf("mismatched target host was not rejected: %v", err)
	}
}

func TestApplyIsBoundedAndStateIsAtomic(t *testing.T) {
	directory := t.TempDir()
	stateFile := filepath.Join(directory, "state.json")
	lockFile := filepath.Join(directory, "helper.lock")
	fake := &fakeRunner{counters: map[string]int64{}}
	var output bytes.Buffer
	id := "2d3880fe-23f0-4bd3-bca2-1eea349b2e2c"
	public, private := testKeys()
	configFile := writeAuthConfig(t, directory, public)

	err := execute(
		strings.NewReader(policyRequest(id, "apply", private)),
		&output,
		fake,
		stateFile,
		lockFile,
		configFile,
	)

	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	current, err := loadState(stateFile)
	if err != nil || len(current.Policies) != 1 || current.Policies[0].ID != id {
		t.Fatalf("unexpected state: %#v, %v", current, err)
	}
	if len(fake.scripts) != 1 ||
		!bytes.Contains(fake.scripts[0], []byte("table inet "+tableName)) {
		t.Fatalf("owned nftables transaction was not generated")
	}
	if bytes.Contains(fake.scripts[0], []byte("shell")) {
		t.Fatalf("unexpected shell content")
	}
}

func TestSnapshotPreservesExactRXAndTXWithoutWeighting(t *testing.T) {
	directory := t.TempDir()
	stateFile := filepath.Join(directory, "state.json")
	lockFile := filepath.Join(directory, "helper.lock")
	id := "2d3880fe-23f0-4bd3-bca2-1eea349b2e2c"
	current := state{
		Version: 1,
		Policies: []policy{{
			ID: id, Protocol: "tcp", Direction: "both", PortStart: 443, PortEnd: 443,
			Mode: "monitor_only", QuotaBytes: 1000, Generation: 1,
			LifetimeRX: 100, LifetimeTX: 200, PeriodStartRX: 50, PeriodStartTX: 75,
		}},
	}
	if err := writeState(stateFile, current); err != nil {
		t.Fatal(err)
	}
	key := policyKey(id)
	fake := &fakeRunner{
		table:    true,
		counters: map[string]int64{key + "_rx": 30, key + "_tx": 40},
	}
	var output bytes.Buffer

	err := execute(
		strings.NewReader(`{"operation":"snapshot"}`),
		&output,
		fake,
		stateFile,
		lockFile,
	)

	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	var result response
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	got := result.Observations[0]
	if got.RXBytesTotal != 130 || got.TXBytesTotal != 240 {
		t.Fatalf("unexpected totals: %#v", got)
	}
	if got.CombinedBytesTotal != 370 {
		t.Fatalf("combined total is not exact RX plus TX: %#v", got)
	}
	if got.CurrentPeriodRX != 80 || got.CurrentPeriodTX != 165 {
		t.Fatalf("unexpected period totals: %#v", got)
	}
	if got.CurrentPeriodTotal != 245 ||
		got.QuotaPercent == nil ||
		*got.QuotaPercent != 24.5 ||
		got.QuotaState != "normal" ||
		got.CollectedAt == "" {
		t.Fatalf("derived policy telemetry is incomplete: %#v", got)
	}
	output.Reset()
	if err := execute(
		strings.NewReader(`{"operation":"snapshot"}`),
		&output,
		fake,
		stateFile,
		lockFile,
	); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Observations[0].RXBytesTotal != 130 ||
		result.Observations[0].TXBytesTotal != 240 {
		t.Fatalf("unchanged kernel counters were counted twice: %#v", result.Observations[0])
	}
	fake.counters[key+"_rx"] = 50
	fake.counters[key+"_tx"] = 70
	output.Reset()
	if err := execute(
		strings.NewReader(`{"operation":"snapshot"}`),
		&output,
		fake,
		stateFile,
		lockFile,
	); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Observations[0].RXBytesTotal != 150 ||
		result.Observations[0].TXBytesTotal != 270 {
		t.Fatalf("kernel counter delta was not checkpointed exactly: %#v", result.Observations[0])
	}
}

func TestSnapshotRestoresOnlyTheDurableOwnedNetworkState(t *testing.T) {
	id := "2d3880fe-23f0-4bd3-bca2-1eea349b2e2c"
	current := state{
		Version: 1,
		Policies: []policy{{
			ID: id, Protocol: "tcp", Direction: "both",
			PortStart: 443, PortEnd: 443, Mode: "monitor_only", Generation: 1,
		}},
		CompletedNonce: map[string]int64{},
	}
	fake := &fakeRunner{counters: map[string]int64{}}
	result, checkpoint, err := snapshot(context.Background(), fake, current)
	if err != nil {
		t.Fatal(err)
	}
	if !fake.table || len(fake.scripts) != 1 {
		t.Fatalf("owned rules were not restored atomically: %#v", fake.scripts)
	}
	if len(result.Observations) != 1 ||
		result.Observations[0].RuntimeRuleState != "active" ||
		result.Observations[0].DiscontinuityReason == nil ||
		*result.Observations[0].DiscontinuityReason != "rule_restore" {
		t.Fatalf("restore discontinuity was not explicit: %#v", result.Observations)
	}
	if checkpoint.Policies[0].LifetimeRX != 0 ||
		checkpoint.Policies[0].LifetimeTX != 0 {
		t.Fatalf("restoration fabricated traffic: %#v", checkpoint.Policies[0])
	}
}

func TestFailedNFTApplyLeavesPreviousState(t *testing.T) {
	directory := t.TempDir()
	stateFile := filepath.Join(directory, "state.json")
	lockFile := filepath.Join(directory, "helper.lock")
	before := state{Version: 1, Policies: []policy{}}
	if err := writeState(stateFile, before); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRunner{counters: map[string]int64{}, failNFT: true}
	var output bytes.Buffer
	public, private := testKeys()
	configFile := writeAuthConfig(t, directory, public)

	err := execute(
		strings.NewReader(
			policyRequest("2d3880fe-23f0-4bd3-bca2-1eea349b2e2c", "apply", private),
		),
		&output,
		fake,
		stateFile,
		lockFile,
		configFile,
	)

	if err == nil {
		t.Fatal("expected nft failure")
	}
	after, loadErr := loadState(stateFile)
	if loadErr != nil || len(after.Policies) != 0 {
		t.Fatalf("state changed after failure: %#v, %v", after, loadErr)
	}
}

func TestPolicyValidationRejectsEnforcementWithoutQuota(t *testing.T) {
	values := map[string]string{
		"id":       "2d3880fe-23f0-4bd3-bca2-1eea349b2e2c",
		"protocol": "tcp", "direction": "both", "port_start": "443", "port_end": "443",
		"mode": "enforcing", "quota_bytes": "0", "egress_rate_bps": "0",
		"counter_generation": "1",
	}
	if _, err := parsePolicy(values, false); err == nil {
		t.Fatal("expected enforcement without quota to be rejected")
	}
}

func TestPolicyKeyUsesTheCompleteUUID(t *testing.T) {
	left := policyKey("12345678-1234-4123-8123-1234567890ab")
	right := policyKey("12345678-1234-4123-8123-1234567890ac")
	if left == right {
		t.Fatal("distinct policy UUIDs must never share a kernel object name")
	}
	if left != "vg_123456781234412381231234567890ab" {
		t.Fatalf("unexpected policy key %q", left)
	}
}

func TestRenderNFTUsesPortableSingletonPortSyntax(t *testing.T) {
	current := state{Version: 1, Policies: []policy{
		{
			ID:       "12345678-1234-4123-8123-1234567890ab",
			Protocol: "tcp", Direction: "both",
			PortStart: 443, PortEnd: 443,
			Mode: "monitor_only", Generation: 1,
		},
		{
			ID:       "12345678-1234-4123-8123-1234567890ac",
			Protocol: "udp", Direction: "rx",
			PortStart: 1000, PortEnd: 1002,
			Mode: "monitor_only", Generation: 1,
		},
	}}
	rendered := string(renderNFT(current, false))
	if strings.Contains(rendered, "443-443") {
		t.Fatal("equal port bounds are not portable across supported nftables versions")
	}
	for _, expected := range []string{"tcp dport 443 ", "tcp sport 443 ", "udp dport 1000-1002 "} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("missing nftables expression %q in %q", expected, rendered)
		}
	}
}

func BenchmarkRenderNFTPolicies(b *testing.B) {
	for _, count := range []int{0, 1, 10, 64} {
		current := state{Version: 1, Policies: make([]policy, 0, count)}
		for index := 0; index < count; index++ {
			current.Policies = append(current.Policies, policy{
				ID:       fmt.Sprintf("00000000-0000-4000-8000-%012d", index),
				Protocol: "both", Direction: "both",
				PortStart: 1000 + index, PortEnd: 1000 + index,
				Mode: "monitor_only", Generation: 1,
			})
		}
		b.Run(fmt.Sprintf("policies_%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_ = renderNFT(current, true)
			}
		})
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add(`{"operation":"snapshot"}`)
	f.Add(`{"operation":"shell","policy":{"command":"nft flush ruleset"}}`)
	f.Add(strings.Repeat("x", 16*1024+1))
	f.Fuzz(func(t *testing.T, value string) {
		request, err := decodeRequest(strings.NewReader(value))
		if err == nil {
			switch request.Operation {
			case "snapshot", "apply", "remove", "reset":
			default:
				t.Fatalf("unexpected accepted operation %q", request.Operation)
			}
		}
	})
}
