package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func testBuildInfo() BuildInfo {
	return BuildInfo{
		Version:      "0.4.0-phase4-rc2",
		GitSHA:       strings.Repeat("a", 40),
		BuildID:      "0.4.0-phase4-rc2+aaaaaaaaaaaa-linux-amd64",
		BuildTime:    "2026-07-25T00:00:00Z",
		GoVersion:    "go1.24.0",
		TargetOS:     "linux",
		TargetArch:   "amd64",
		Dirty:        false,
		BinarySHA256: strings.Repeat("b", 64),
	}
}

func TestVersionCommandsExitBeforeConfigOrAgentLoop(t *testing.T) {
	for _, command := range []string{"version", "--version"} {
		t.Run(command, func(t *testing.T) {
			var output bytes.Buffer
			dependencies := cliDependencies{
				buildInfo: func() (BuildInfo, error) { return testBuildInfo(), nil },
				loadConfig: func(string) (Config, error) {
					t.Fatal("version command loaded Agent configuration")
					return Config{}, nil
				},
				run: func(Config, BuildInfo) error {
					t.Fatal("version command entered the Agent main loop")
					return nil
				},
			}
			if code := executeCLI([]string{command}, &output, &output, dependencies); code != 0 {
				t.Fatalf("version command returned %d: %s", code, output.String())
			}
			for _, expected := range []string{
				"version=0.4.0-phase4-rc2",
				"git_sha=" + strings.Repeat("a", 40),
				"build_id=0.4.0-phase4-rc2+aaaaaaaaaaaa-linux-amd64",
				"build_time=2026-07-25T00:00:00Z",
				"go_version=go1.24.0",
				"target_os=linux",
				"target_arch=amd64",
				"dirty=false",
				"artifact_sha256=" + strings.Repeat("b", 64),
			} {
				if !strings.Contains(output.String(), expected+"\n") {
					t.Fatalf("version output is missing %q: %s", expected, output.String())
				}
			}
		})
	}
}

func TestCurrentBuildInfoHashesTheRunningArtifact(t *testing.T) {
	info, err := currentBuildInfo()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(info.BinarySHA256) {
		t.Fatalf("unexpected artifact SHA-256: %q", info.BinarySHA256)
	}
	if info.GoVersion == "" || info.TargetOS == "" || info.TargetArch == "" {
		t.Fatalf("runtime provenance is incomplete: %#v", info)
	}
}
