package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type response struct {
	Status       string        `json:"status"`
	Generation   int64         `json:"generation,omitempty"`
	Observations []observation `json:"observations,omitempty"`
}

type observation struct {
	PolicyID             string          `json:"policy_id"`
	RXBytesTotal         int64           `json:"rx_bytes_total"`
	TXBytesTotal         int64           `json:"tx_bytes_total"`
	CombinedBytesTotal   int64           `json:"combined_bytes_total"`
	CurrentPeriodRX      int64           `json:"current_period_rx"`
	CurrentPeriodTX      int64           `json:"current_period_tx"`
	CurrentPeriodTotal   int64           `json:"current_period_total"`
	QuotaBytes           *int64          `json:"quota_bytes"`
	QuotaPercent         *float64        `json:"quota_percent"`
	QuotaState           string          `json:"quota_state"`
	ResetPolicy          json.RawMessage `json:"reset_policy"`
	CurrentPeriodStart   *string         `json:"current_period_start"`
	NextResetAt          *string         `json:"next_reset_at"`
	LastResetAt          *string         `json:"last_reset_at"`
	CounterGeneration    int64           `json:"counter_generation"`
	RuntimeRuleState     string          `json:"runtime_rule_state"`
	ShapingState         string          `json:"shaping_state"`
	CurrentEgressRateBPS *int64          `json:"current_egress_rate_bps"`
	CollectedAt          string          `json:"collected_at"`
	DiscontinuityReason  *string         `json:"discontinuity_reason"`
}

func decodeRequest(input io.Reader) (request, error) {
	data, err := io.ReadAll(io.LimitReader(input, 16*1024+1))
	if err != nil || len(data) == 0 || len(data) > 16*1024 {
		return request{}, errors.New("request exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value request
	if err := decoder.Decode(&value); err != nil {
		return request{}, errors.New("request JSON is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return request{}, errors.New("request JSON has trailing content")
	}
	if value.Operation != "snapshot" &&
		value.Operation != "apply" &&
		value.Operation != "remove" &&
		value.Operation != "reset" {
		return request{}, errors.New("operation is invalid")
	}
	return value, nil
}

func findPolicy(items []policy, id string) int {
	for index := range items {
		if items[index].ID == id {
			return index
		}
	}
	return -1
}

func overlaps(left, right policy) bool {
	protocolOverlap := left.Protocol == "both" ||
		right.Protocol == "both" ||
		left.Protocol == right.Protocol
	return protocolOverlap && left.PortStart <= right.PortEnd && right.PortStart <= left.PortEnd
}

func desiredState(current state, request request, parsed policy) (state, int64, error) {
	next := current
	next.Policies = append([]policy(nil), current.Policies...)
	index := findPolicy(next.Policies, parsed.ID)
	switch request.Operation {
	case "apply":
		if index < 0 {
			if len(next.Policies) >= maxPolicies {
				return state{}, 0, errors.New("policy limit reached")
			}
			for _, existing := range next.Policies {
				if overlaps(parsed, existing) {
					return state{}, 0, errors.New("policy overlaps an owned rule")
				}
			}
			parsed.PeriodStarted = time.Now().Unix()
			next.Policies = append(next.Policies, parsed)
		} else {
			parsed.LifetimeRX = next.Policies[index].LifetimeRX
			parsed.LifetimeTX = next.Policies[index].LifetimeTX
			parsed.PeriodStartRX = next.Policies[index].PeriodStartRX
			parsed.PeriodStartTX = next.Policies[index].PeriodStartTX
			parsed.PeriodStarted = next.Policies[index].PeriodStarted
			parsed.LastResetAt = next.Policies[index].LastResetAt
			parsed.Generation = next.Policies[index].Generation
			next.Policies[index] = parsed
		}
	case "remove":
		if index < 0 {
			return current, parsed.Generation, nil
		}
		next.Policies = append(next.Policies[:index], next.Policies[index+1:]...)
	case "reset":
		if index < 0 {
			return state{}, 0, errors.New("policy does not exist")
		}
		next.Policies[index].PeriodStartRX = next.Policies[index].LifetimeRX
		next.Policies[index].PeriodStartTX = next.Policies[index].LifetimeTX
		next.Policies[index].PeriodStarted = time.Now().Unix()
		next.Policies[index].LastResetAt = next.Policies[index].PeriodStarted
		next.Policies[index].ResetPolicy = parsed.ResetPolicy
		next.Policies[index].NextResetAt = parsed.NextResetAt
		next.Policies[index].Generation++
		return next, next.Policies[index].Generation, nil
	}
	if position := findPolicy(next.Policies, parsed.ID); position >= 0 {
		return next, next.Policies[position].Generation, nil
	}
	return next, parsed.Generation, nil
}

func snapshot(ctx context.Context, commands runner, current state) (response, state, error) {
	raw, err := readCounters(ctx, commands)
	if err != nil {
		return response{}, current, err
	}
	restored := false
	if err := verifyNetwork(ctx, commands, current, current); err != nil {
		// Only restore the root-owned, previously authorized durable state.
		// Absorb any surviving counters before a transaction can recreate
		// missing objects, so a failed restore cannot lose accounting data.
		current = absorbCounters(current, raw)
		if restoreErr := applyNetwork(ctx, commands, current, current); restoreErr == nil {
			restored = true
		}
		raw, err = readCounters(ctx, commands)
		if err != nil {
			return response{}, current, err
		}
	}
	checkpoint := current
	checkpoint.Policies = append([]policy(nil), current.Policies...)
	shapingStates := readShapingStates(ctx, commands, checkpoint)
	observations := make([]observation, 0, len(checkpoint.Policies))
	collectedAt := time.Now().UTC()
	for index := range checkpoint.Policies {
		item := &checkpoint.Policies[index]
		key := policyKey(item.ID)
		rawRX, rxPresent := raw[key+"_rx"]
		rawTX, txPresent := raw[key+"_tx"]
		if item.Direction == "tx" {
			rxPresent = true
		}
		if item.Direction == "rx" {
			txPresent = true
		}
		if rxPresent && rawRX >= item.LastKernelRX {
			item.LifetimeRX += rawRX - item.LastKernelRX
			item.LastKernelRX = rawRX
		}
		if txPresent && rawTX >= item.LastKernelTX {
			item.LifetimeTX += rawTX - item.LastKernelTX
			item.LastKernelTX = rawTX
		}
		totalRX := item.LifetimeRX
		totalTX := item.LifetimeTX
		ruleState := "active"
		var discontinuity *string
		if restored {
			reason := "rule_restore"
			discontinuity = &reason
		} else if !rxPresent || !txPresent {
			ruleState = "missing"
			reason := "rule_missing"
			discontinuity = &reason
		}
		shaping := shapingStates[item.ID]
		var currentRate *int64
		if item.EgressRateBPS > 0 {
			rate := item.EgressRateBPS
			currentRate = &rate
		}
		var quota *int64
		var quotaPercent *float64
		quotaState := "unlimited"
		if item.QuotaBytes > 0 {
			value := item.QuotaBytes
			quota = &value
			percent := float64(
				totalRX-item.PeriodStartRX+totalTX-item.PeriodStartTX,
			) * 100 / float64(item.QuotaBytes)
			quotaPercent = &percent
			switch {
			case percent >= 100:
				quotaState = "exhausted"
			case percent >= 95:
				quotaState = "critical"
			case percent >= 70:
				quotaState = "warning"
			default:
				quotaState = "normal"
			}
		}
		resetPolicy := json.RawMessage(item.ResetPolicy)
		if !json.Valid(resetPolicy) {
			resetPolicy = json.RawMessage(`{"type":"manual"}`)
		}
		periodStart := unixTimestamp(item.PeriodStarted)
		lastReset := unixTimestamp(item.LastResetAt)
		nextReset := optionalString(item.NextResetAt)
		periodRX := totalRX - item.PeriodStartRX
		periodTX := totalTX - item.PeriodStartTX
		observations = append(observations, observation{
			PolicyID: item.ID, RXBytesTotal: totalRX, TXBytesTotal: totalTX,
			CombinedBytesTotal: totalRX + totalTX,
			CurrentPeriodRX:    periodRX, CurrentPeriodTX: periodTX,
			CurrentPeriodTotal: periodRX + periodTX,
			QuotaBytes:         quota, QuotaPercent: quotaPercent, QuotaState: quotaState,
			ResetPolicy: resetPolicy, CurrentPeriodStart: periodStart,
			NextResetAt: nextReset, LastResetAt: lastReset,
			CounterGeneration: item.Generation,
			RuntimeRuleState:  ruleState, ShapingState: shaping,
			CurrentEgressRateBPS: currentRate,
			CollectedAt:          collectedAt.Format(time.RFC3339Nano),
			DiscontinuityReason:  discontinuity,
		})
	}
	return response{Status: "ok", Observations: observations}, checkpoint, nil
}

func unixTimestamp(value int64) *string {
	if value <= 0 {
		return nil
	}
	formatted := time.Unix(value, 0).UTC().Format(time.RFC3339)
	return &formatted
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func execute(input io.Reader, output io.Writer, commands runner, paths ...string) error {
	request, err := decodeRequest(input)
	if err != nil {
		return err
	}
	return executeRequest(request, output, commands, paths...)
}

func executeRequest(
	request request,
	output io.Writer,
	commands runner,
	paths ...string,
) error {
	selectedStatePath := statePath
	selectedLockPath := lockPath
	selectedAgentConfigPath := agentConfigPath
	if len(paths) >= 2 {
		selectedStatePath, selectedLockPath = paths[0], paths[1]
	}
	if len(paths) == 3 {
		selectedAgentConfigPath = paths[2]
	}
	release, err := acquireLock(selectedLockPath)
	if err != nil {
		return err
	}
	defer release()
	current, err := loadState(selectedStatePath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if request.Operation == "snapshot" {
		result, checkpoint, err := snapshot(ctx, commands, current)
		if err != nil {
			return err
		}
		if err := writeState(selectedStatePath, checkpoint); err != nil {
			return errors.New("counter checkpoint could not be committed")
		}
		return json.NewEncoder(output).Encode(result)
	}
	if request.Operation == "purge" {
		raw := map[string]int64{}
		if tableExists(ctx, commands) {
			raw, err = readCounters(ctx, commands)
			if err != nil {
				return err
			}
		}
		baseline := absorbCounters(current, raw)
		desired := state{
			Version: 1, Policies: []policy{}, CompletedNonce: map[string]int64{},
		}
		if !request.DryRun {
			if err := applyNetwork(ctx, commands, baseline, desired); err != nil {
				return err
			}
			if err := writeState(selectedStatePath, desired); err != nil {
				_ = applyNetwork(ctx, commands, desired, baseline)
				_ = writeState(selectedStatePath, baseline)
				return errors.New("state commit failed; network state rolled back")
			}
		}
		return json.NewEncoder(output).Encode(response{Status: "ok"})
	}
	publicKey, expectedHostID, err := loadControllerTrust(selectedAgentConfigPath)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := verifyAuthorization(
		request,
		publicKey,
		expectedHostID,
		current.CompletedNonce,
		now,
	); err != nil {
		return err
	}
	parsed, err := parsePolicy(request.Policy, !request.DryRun)
	if err != nil {
		return err
	}
	raw := map[string]int64{}
	if tableExists(ctx, commands) {
		raw, err = readCounters(ctx, commands)
		if err != nil {
			return err
		}
	}
	baseline := absorbCounters(current, raw)
	desired, generation, err := desiredState(baseline, request, parsed)
	if err != nil {
		return err
	}
	if request.DryRun {
		preflight := baseline
		preflight.CompletedNonce = make(map[string]int64, len(baseline.CompletedNonce))
		for nonce, expiry := range baseline.CompletedNonce {
			preflight.CompletedNonce[nonce] = expiry
		}
		consumeNonce(
			&preflight,
			request.Authorization.Nonce,
			request.Authorization.ExpiresAt,
			now,
		)
		if err := writeState(selectedStatePath, preflight); err != nil {
			return errors.New("authorization nonce could not be committed")
		}
		return json.NewEncoder(output).Encode(response{Status: "ok", Generation: generation})
	}
	consumeNonce(
		&desired,
		request.Authorization.Nonce,
		request.Authorization.ExpiresAt,
		now,
	)
	if err := applyNetwork(ctx, commands, baseline, desired); err != nil {
		return err
	}
	if err := writeState(selectedStatePath, desired); err != nil {
		_ = applyNetwork(ctx, commands, desired, baseline)
		_ = writeState(selectedStatePath, baseline)
		return errors.New("state commit failed; network state rolled back")
	}
	return json.NewEncoder(output).Encode(response{Status: "ok", Generation: generation})
}

func main() {
	var err error
	if len(os.Args) == 2 && os.Args[1] == "--purge-owned-state" && os.Geteuid() == 0 {
		err = executeRequest(request{Operation: "purge"}, os.Stdout, commandRunner{})
	} else if len(os.Args) == 1 {
		err = execute(os.Stdin, os.Stdout, commandRunner{})
	} else {
		err = errors.New("arguments are invalid")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "request rejected")
		os.Exit(1)
	}
}
