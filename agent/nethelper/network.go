package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

type runner interface {
	run(context.Context, string, []string, []byte) ([]byte, error)
}

type commandRunner struct{}

func (commandRunner) run(
	ctx context.Context,
	name string,
	arguments []string,
	input []byte,
) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	output, err := command.CombinedOutput()
	if len(output) > 256*1024 {
		return nil, errors.New("network command output exceeds limit")
	}
	if err != nil {
		return nil, fmt.Errorf("%s failed", name)
	}
	return output, nil
}

func tableExists(ctx context.Context, commands runner) bool {
	_, err := commands.run(
		ctx,
		"nft",
		[]string{"list", "table", "inet", tableName},
		nil,
	)
	return err == nil
}

func renderNFT(current state, exists bool) []byte {
	var output strings.Builder
	if len(current.Policies) == 0 {
		if exists {
			fmt.Fprintf(&output, "delete table inet %s\n", tableName)
		}
		return []byte(output.String())
	}
	if exists {
		fmt.Fprintf(&output, "flush table inet %s\n", tableName)
	} else {
		fmt.Fprintf(&output, "add table inet %s\n", tableName)
	}
	fmt.Fprintf(
		&output,
		"add chain inet %s ingress { type filter hook input priority -10; policy accept; }\n",
		tableName,
	)
	fmt.Fprintf(
		&output,
		"add chain inet %s egress { type filter hook output priority -10; policy accept; }\n",
		tableName,
	)
	sorted := append([]policy(nil), current.Policies...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].ID < sorted[right].ID })
	for _, item := range sorted {
		key := policyKey(item.ID)
		if item.Direction == "rx" || item.Direction == "both" {
			fmt.Fprintf(&output, "add counter inet %s %s_rx\n", tableName, key)
		}
		if item.Direction == "tx" || item.Direction == "both" {
			fmt.Fprintf(&output, "add counter inet %s %s_tx\n", tableName, key)
		}
		if item.Mode == "enforcing" {
			used := (item.LifetimeRX - item.PeriodStartRX) +
				(item.LifetimeTX - item.PeriodStartTX)
			remaining := item.QuotaBytes - used
			if remaining < 1 {
				remaining = 1
			}
			fmt.Fprintf(
				&output,
				"add quota inet %s %s_quota { over %d bytes; }\n",
				tableName,
				key,
				remaining,
			)
		}
		for _, protocol := range protocols(item.Protocol) {
			interfaceRX := ""
			interfaceTX := ""
			if item.InterfaceName != "" {
				interfaceRX = fmt.Sprintf("iifname %q ", item.InterfaceName)
				interfaceTX = fmt.Sprintf("oifname %q ", item.InterfaceName)
			}
			enforce := ""
			if item.Mode == "enforcing" {
				enforce = fmt.Sprintf(" quota name %s_quota drop", key)
			}
			if item.Direction == "rx" || item.Direction == "both" {
				fmt.Fprintf(
					&output,
					"add rule inet %s ingress %smeta l4proto %s %s dport %d-%d counter name %s_rx%s\n",
					tableName,
					interfaceRX,
					protocol,
					protocol,
					item.PortStart,
					item.PortEnd,
					key,
					enforce,
				)
			}
			if item.Direction == "tx" || item.Direction == "both" {
				fmt.Fprintf(
					&output,
					"add rule inet %s egress %smeta l4proto %s %s sport %d-%d counter name %s_tx%s\n",
					tableName,
					interfaceTX,
					protocol,
					protocol,
					item.PortStart,
					item.PortEnd,
					key,
					enforce,
				)
			}
		}
	}
	return []byte(output.String())
}

func readCounters(ctx context.Context, commands runner) (map[string]int64, error) {
	output, err := commands.run(ctx, "nft", []string{"-j", "list", "ruleset"}, nil)
	if err != nil {
		return nil, err
	}
	var document any
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, errors.New("nft JSON is invalid")
	}
	counters := map[string]int64{}
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				visit(item)
			}
		case map[string]any:
			if raw, ok := typed["counter"].(map[string]any); ok {
				table, _ := raw["table"].(string)
				name, _ := raw["name"].(string)
				bytesValue, _ := raw["bytes"].(float64)
				if table == tableName && strings.HasPrefix(name, "vg_") && bytesValue >= 0 {
					counters[name] = int64(bytesValue)
				}
			}
			for _, item := range typed {
				visit(item)
			}
		}
	}
	visit(document)
	return counters, nil
}

func absorbCounters(current state, raw map[string]int64) state {
	next := current
	next.Policies = append([]policy(nil), current.Policies...)
	for index := range next.Policies {
		key := policyKey(next.Policies[index].ID)
		rawRX := raw[key+"_rx"]
		rawTX := raw[key+"_tx"]
		if rawRX >= next.Policies[index].LastKernelRX {
			next.Policies[index].LifetimeRX +=
				rawRX - next.Policies[index].LastKernelRX
		}
		if rawTX >= next.Policies[index].LastKernelTX {
			next.Policies[index].LifetimeTX +=
				rawTX - next.Policies[index].LastKernelTX
		}
		next.Policies[index].LastKernelRX = 0
		next.Policies[index].LastKernelTX = 0
	}
	return next
}

func qdiscStatus(output []byte) (guardian bool, otherRoot bool) {
	var qdiscs []map[string]any
	if json.Unmarshal(output, &qdiscs) != nil {
		return false, true
	}
	for _, qdisc := range qdiscs {
		if root, _ := qdisc["root"].(bool); !root {
			continue
		}
		handle, _ := qdisc["handle"].(string)
		kind, _ := qdisc["kind"].(string)
		if kind == "noqueue" {
			continue
		}
		if handle == tcHandle && kind == "htb" {
			guardian = true
		} else {
			otherRoot = true
		}
	}
	return guardian, otherRoot
}

func ownedQdisc(output []byte) bool {
	_, otherRoot := qdiscStatus(output)
	return !otherRoot
}

func shapingByInterface(current state) map[string][]policy {
	output := map[string][]policy{}
	for _, item := range current.Policies {
		if item.EgressRateBPS > 0 {
			output[item.InterfaceName] = append(output[item.InterfaceName], item)
		}
	}
	return output
}

func readShapingStates(
	ctx context.Context,
	commands runner,
	current state,
) map[string]string {
	states := make(map[string]string, len(current.Policies))
	interfaceStates := map[string]string{}
	for name := range shapingByInterface(current) {
		output, err := commands.run(
			ctx,
			"tc",
			[]string{"-j", "qdisc", "show", "dev", name},
			nil,
		)
		state := "inconsistent"
		if err == nil {
			guardian, otherRoot := qdiscStatus(output)
			if guardian && !otherRoot {
				state = "active"
			}
		}
		interfaceStates[name] = state
	}
	for _, item := range current.Policies {
		if item.EgressRateBPS == 0 {
			states[item.ID] = "disabled"
		} else {
			states[item.ID] = interfaceStates[item.InterfaceName]
		}
	}
	return states
}

func preflightTCOwnership(
	ctx context.Context,
	commands runner,
	before state,
	desired state,
) error {
	interfaces := map[string]bool{}
	for name := range shapingByInterface(before) {
		interfaces[name] = true
	}
	for name := range shapingByInterface(desired) {
		interfaces[name] = true
	}
	for name := range interfaces {
		if name == "" {
			return errors.New("egress shaping requires an explicit interface")
		}
		output, err := commands.run(
			ctx,
			"tc",
			[]string{"-j", "qdisc", "show", "dev", name},
			nil,
		)
		if err != nil || !ownedQdisc(output) {
			return errors.New("refusing to replace a non-Guardian root qdisc")
		}
	}
	return nil
}

func applyTC(ctx context.Context, commands runner, before, desired state) error {
	interfaces := map[string]bool{}
	for name := range shapingByInterface(before) {
		interfaces[name] = true
	}
	for name := range shapingByInterface(desired) {
		interfaces[name] = true
	}
	for name := range interfaces {
		if name == "" {
			return errors.New("egress shaping requires an explicit interface")
		}
		output, err := commands.run(ctx, "tc", []string{"-j", "qdisc", "show", "dev", name}, nil)
		if err != nil || !ownedQdisc(output) {
			return errors.New("refusing to replace a non-Guardian root qdisc")
		}
		items := shapingByInterface(desired)[name]
		if len(items) == 0 {
			_, _ = commands.run(ctx, "tc", []string{"qdisc", "del", "dev", name, "root", "handle", tcHandle}, nil)
			continue
		}
		if _, err := commands.run(
			ctx,
			"tc",
			[]string{"qdisc", "replace", "dev", name, "root", "handle", tcHandle, "htb", "default", "4095"},
			nil,
		); err != nil {
			return err
		}
		if _, err := commands.run(
			ctx,
			"tc",
			[]string{
				"class", "replace", "dev", name, "parent", tcHandle,
				"classid", "7a11:4095", "htb", "rate", "100gbit", "ceil", "100gbit",
			},
			nil,
		); err != nil {
			return err
		}
		for index, item := range items {
			class := fmt.Sprintf("7a11:%d", index+1)
			rate := fmt.Sprintf("%dbit", item.EgressRateBPS)
			if _, err := commands.run(
				ctx,
				"tc",
				[]string{"class", "replace", "dev", name, "parent", tcHandle, "classid", class, "htb", "rate", rate, "ceil", rate},
				nil,
			); err != nil {
				return err
			}
			for protocolIndex, protocol := range protocols(item.Protocol) {
				for familyIndex, family := range []string{"ip", "ipv6"} {
					priority := index*4 + protocolIndex*2 + familyIndex + 1
					port := fmt.Sprintf("%d", item.PortStart)
					if item.PortStart != item.PortEnd {
						port = fmt.Sprintf("%d-%d", item.PortStart, item.PortEnd)
					}
					arguments := []string{
						"filter", "replace", "dev", name, "protocol", family,
						"parent", tcHandle, "prio", fmt.Sprintf("%d", priority),
						"flower", "ip_proto", protocol, "src_port", port,
						"classid", class,
					}
					if _, err := commands.run(ctx, "tc", arguments, nil); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func applyNetwork(ctx context.Context, commands runner, before, desired state) error {
	if err := preflightTCOwnership(ctx, commands, before, desired); err != nil {
		return err
	}
	exists := tableExists(ctx, commands)
	nftTransaction := renderNFT(desired, exists)
	if len(nftTransaction) > 0 {
		if _, err := commands.run(ctx, "nft", []string{"-f", "-"}, nftTransaction); err != nil {
			return err
		}
	}
	if err := applyTC(ctx, commands, before, desired); err != nil {
		rollbackExists := len(desired.Policies) > 0
		rollback := renderNFT(before, rollbackExists)
		if len(rollback) > 0 {
			_, _ = commands.run(ctx, "nft", []string{"-f", "-"}, rollback)
		}
		_ = applyTC(ctx, commands, desired, before)
		return err
	}
	if err := verifyNetwork(ctx, commands, before, desired); err != nil {
		rollbackExists := len(desired.Policies) > 0
		rollback := renderNFT(before, rollbackExists)
		if len(rollback) > 0 {
			_, _ = commands.run(ctx, "nft", []string{"-f", "-"}, rollback)
		}
		_ = applyTC(ctx, commands, desired, before)
		return err
	}
	return nil
}

func verifyNetwork(ctx context.Context, commands runner, before, desired state) error {
	if len(desired.Policies) == 0 {
		if tableExists(ctx, commands) {
			return errors.New("owned nftables table remained after removal")
		}
	} else {
		if !tableExists(ctx, commands) {
			return errors.New("owned nftables table is missing after apply")
		}
		counters, err := readCounters(ctx, commands)
		if err != nil {
			return errors.New("owned nftables counters could not be verified")
		}
		for _, item := range desired.Policies {
			key := policyKey(item.ID)
			if item.Direction != "tx" {
				if _, present := counters[key+"_rx"]; !present {
					return errors.New("owned RX counter is missing after apply")
				}
			}
			if item.Direction != "rx" {
				if _, present := counters[key+"_tx"]; !present {
					return errors.New("owned TX counter is missing after apply")
				}
			}
		}
	}
	interfaces := map[string]bool{}
	for name := range shapingByInterface(before) {
		interfaces[name] = true
	}
	for name := range shapingByInterface(desired) {
		interfaces[name] = true
	}
	for name := range interfaces {
		output, err := commands.run(ctx, "tc", []string{"-j", "qdisc", "show", "dev", name}, nil)
		if err != nil {
			return errors.New("egress qdisc could not be verified")
		}
		guardian, otherRoot := qdiscStatus(output)
		expectGuardian := len(shapingByInterface(desired)[name]) > 0
		if otherRoot || guardian != expectGuardian {
			return errors.New("egress qdisc post-check failed")
		}
	}
	return nil
}
