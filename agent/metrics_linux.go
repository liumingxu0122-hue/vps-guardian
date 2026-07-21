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

func decodeMountPath(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

func collectMounts() []map[string]any {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return []map[string]any{}
	}
	defer file.Close()
	mounts := []map[string]any{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() && len(mounts) < 256 {
		parts := strings.SplitN(scanner.Text(), " - ", 2)
		fields := strings.Fields(parts[0])
		if len(parts) != 2 || len(fields) < 6 {
			continue
		}
		mountPath := decodeMountPath(fields[4])
		if seen[mountPath] {
			continue
		}
		var stats syscall.Statfs_t
		if err := syscall.Statfs(mountPath, &stats); err != nil {
			continue
		}
		seen[mountPath] = true
		total := stats.Blocks * uint64(stats.Bsize)
		free := stats.Bavail * uint64(stats.Bsize)
		entry := map[string]any{
			"path":        mountPath,
			"filesystem":  strings.Fields(parts[1])[0],
			"total_bytes": total,
			"free_bytes":  free,
			"inode_total": stats.Files,
			"inode_free":  stats.Ffree,
		}
		if total > 0 && free <= total {
			entry["used_percent"] = float64(total-free) * 100 / float64(total)
		}
		if stats.Files > 0 && stats.Ffree <= stats.Files {
			entry["inode_used_percent"] = float64(stats.Files-stats.Ffree) * 100 / float64(stats.Files)
		}
		mounts = append(mounts, entry)
	}
	return mounts
}

func readOSRelease() map[string]string {
	result := map[string]string{}
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.Trim(parts[1], `"`)
		switch parts[0] {
		case "ID", "VERSION_ID", "PRETTY_NAME":
			result[strings.ToLower(parts[0])] = value
		}
	}
	return result
}

func readSelfRSS() uint64 {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			return value * 1024
		}
	}
	return 0
}

func timevalSeconds(value syscall.Timeval) float64 {
	return float64(value.Sec) + float64(value.Usec)/1_000_000
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
	metrics["architecture"] = runtime.GOARCH
	metrics["operating_system"] = readOSRelease()
	metrics["kernel_version"] = readFirstLine("/proc/sys/kernel/osrelease")
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
		uptimeSeconds, _ := strconv.ParseFloat(uptime[0], 64)
		metrics["uptime_seconds"] = uptimeSeconds
		metrics["boot_time"] = time.Now().Add(-time.Duration(uptimeSeconds * float64(time.Second))).UTC().Format(time.RFC3339)
	}
	if total, totalOK := metrics["memory_total_bytes"].(uint64); totalOK && total > 0 {
		if available, availableOK := metrics["memory_available_bytes"].(uint64); availableOK && available <= total {
			metrics["memory_percent"] = float64(total-available) * 100 / float64(total)
		}
	}
	if total, totalOK := metrics["swap_total_bytes"].(uint64); totalOK && total > 0 {
		if free, freeOK := metrics["swap_free_bytes"].(uint64); freeOK && free <= total {
			metrics["swap_percent"] = float64(total-free) * 100 / float64(total)
		}
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
		total := disk.Blocks * uint64(disk.Bsize)
		free := disk.Bavail * uint64(disk.Bsize)
		if total > 0 && free <= total {
			metrics["disk_percent"] = float64(total-free) * 100 / float64(total)
		}
	}
	metrics["mounts"] = collectMounts()
	receive, transmit := readNetworkBytes()
	metrics["network_rx_bytes"] = receive
	metrics["network_tx_bytes"] = transmit
	metrics["agent_rss_bytes"] = readSelfRSS()
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) == nil {
		metrics["agent_cpu_seconds"] = timevalSeconds(usage.Utime) + timevalSeconds(usage.Stime)
	}
	return metrics, nil
}
