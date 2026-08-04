package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

var (
	agentVersion = "0.4.0-alpha.1"
	buildCommit  = "unknown"
	buildTime    = "unknown"
	buildID      = "development"
	buildDirty   = "true"
)

type BuildInfo struct {
	Version      string `json:"version"`
	GitSHA       string `json:"git_sha"`
	BuildID      string `json:"build_id"`
	BuildTime    string `json:"build_time"`
	GoVersion    string `json:"go_version"`
	TargetOS     string `json:"os"`
	TargetArch   string `json:"arch"`
	Dirty        bool   `json:"dirty"`
	BinarySHA256 string `json:"binary_sha256"`
}

func executableSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve Agent executable: %w", err)
	}
	handle, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open Agent executable: %w", err)
	}
	defer handle.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, handle); err != nil {
		return "", fmt.Errorf("hash Agent executable: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func currentBuildInfo() (BuildInfo, error) {
	binarySHA256, err := executableSHA256()
	if err != nil {
		return BuildInfo{}, err
	}
	return BuildInfo{
		Version:      agentVersion,
		GitSHA:       buildCommit,
		BuildID:      buildID,
		BuildTime:    buildTime,
		GoVersion:    runtime.Version(),
		TargetOS:     runtime.GOOS,
		TargetArch:   runtime.GOARCH,
		Dirty:        strings.EqualFold(buildDirty, "true"),
		BinarySHA256: binarySHA256,
	}, nil
}

func printBuildInfo(output io.Writer, info BuildInfo) {
	fmt.Fprintf(output, "version=%s\n", info.Version)
	fmt.Fprintf(output, "git_sha=%s\n", info.GitSHA)
	fmt.Fprintf(output, "build_id=%s\n", info.BuildID)
	fmt.Fprintf(output, "build_time=%s\n", info.BuildTime)
	fmt.Fprintf(output, "go_version=%s\n", info.GoVersion)
	fmt.Fprintf(output, "target_os=%s\n", info.TargetOS)
	fmt.Fprintf(output, "target_arch=%s\n", info.TargetArch)
	fmt.Fprintf(output, "dirty=%t\n", info.Dirty)
	fmt.Fprintf(output, "artifact_sha256=%s\n", info.BinarySHA256)
}
