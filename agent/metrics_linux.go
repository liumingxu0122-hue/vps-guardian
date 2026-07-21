//go:build linux

package main

import (
	"bufio"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var errUnsupportedPlatform = errors.New("unsupported platform")

func readCPUTimes() (uint64, uint64, bool) {
	fields := strings.Fields(readFirstLine("/proc/stat"))
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	var total uint64
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		values = append(values, value)
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return total, idle, true
}

func readNetworkBytes() (uint64, uint64) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer file.Close()
	var receive, transmit uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(strings.ReplaceAll(scanner.Text(), ":", " "))
		if len(parts) < 17 || parts[0] == "lo" {
			continue
		}
		rx, rxErr := strconv.ParseUint(parts[1], 10, 64)
		tx, txErr := strconv.ParseUint(parts[9], 10, 64)
		if rxErr == nil && txErr == nil {
			receive += rx
			transmit += tx
		}
	}
	return receive, transmit
}

func readFirstLine(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

func collectHostMetrics(diskPath string) (map[string]any, error) {
	metrics := map[string]any{}
	metrics["cpu_count"] = runtime.NumCPU()
	firstTotal, firstIdle, firstOK := readCPUTimes()
	if firstOK {
		time.Sleep(100 * time.Millisecond)
		secondTotal, secondIdle, secondOK := readCPUTimes()
		if secondOK && secondTotal > firstTotal && secondIdle >= firstIdle {
			totalDelta := secondTotal - firstTotal
			idleDelta := secondIdle - firstIdle
			if idleDelta <= totalDelta {
				metrics["cpu_percent"] = float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
			}
		}
	}
	load := strings.Fields(readFirstLine("/proc/loadavg"))
	if len(load) >= 3 {
		metrics["load_1"], _ = strconv.ParseFloat(load[0], 64)
		metrics["load_5"], _ = strconv.ParseFloat(load[1], 64)
		metrics["load_15"], _ = strconv.ParseFloat(load[2], 64)
	}
	uptime := strings.Fields(readFirstLine("/proc/uptime"))
	if len(uptime) > 0 {
		metrics["uptime_seconds"], _ = strconv.ParseFloat(uptime[0], 64)
	}
	if file, err := os.Open("/proc/meminfo"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) < 2 {
				continue
			}
			value, _ := strconv.ParseUint(parts[1], 10, 64)
			switch strings.TrimSuffix(parts[0], ":") {
			case "MemTotal":
				metrics["memory_total_bytes"] = value * 1024
			case "MemAvailable":
				metrics["memory_available_bytes"] = value * 1024
			case "SwapTotal":
				metrics["swap_total_bytes"] = value * 1024
			case "SwapFree":
				metrics["swap_free_bytes"] = value * 1024
			}
		}
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs(diskPath, &disk); err == nil {
		metrics["disk_total_bytes"] = disk.Blocks * uint64(disk.Bsize)
		metrics["disk_free_bytes"] = disk.Bavail * uint64(disk.Bsize)
		metrics["inode_total"] = disk.Files
		metrics["inode_free"] = disk.Ffree
	}
	receive, transmit := readNetworkBytes()
	metrics["network_rx_bytes"] = receive
	metrics["network_tx_bytes"] = transmit
	return metrics, nil
}
