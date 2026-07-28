package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(config Config, build BuildInfo) error {
	queue := NewDiskQueue(config.QueueFile, config.MaxQueueBytes)
	client, err := NewControllerClient(config)
	if err != nil {
		return err
	}
	registry := NewActionRegistry(config)
	pendingChecks := []RemoteCheck{}
	nextRenewalAttempt := time.Time{}
	ticker := time.NewTicker(time.Duration(config.HeartbeatInterval))
	defer ticker.Stop()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for {
		snapshot, err := collectSnapshot(
			config,
			queue,
			pendingChecks,
			registry.RestartCount(),
			build,
		)
		if err != nil {
			log.Printf("snapshot collection failed: %v", err)
		} else {
			response, heartbeatErr := client.Heartbeat(ctx, snapshot)
			if heartbeatErr != nil {
				encoded, _ := json.Marshal(snapshot)
				_ = queue.Enqueue(map[string]any{"type": "heartbeat_failed", "at": time.Now().UTC().Format(time.RFC3339), "summary_sha256": sha256String(encoded)})
				log.Printf("controller heartbeat unavailable: %v", heartbeatErr)
			} else if response.Accepted {
				if client.CertificateExpiresWithin(time.Now(), time.Duration(config.CertificateRenewBefore)) &&
					time.Now().After(nextRenewalAttempt) {
					replacement, renewalErr := client.RenewCertificate(ctx, response.IdentityVersion)
					if renewalErr != nil {
						nextRenewalAttempt = time.Now().Add(time.Hour)
						log.Printf("certificate renewal failed; retry deferred: %v", renewalErr)
					} else {
						client = replacement
						nextRenewalAttempt = time.Time{}
						log.Printf("certificate identity renewed to generation %d", response.IdentityVersion+1)
					}
				}
				pendingChecks = response.Checks
				_ = queue.Ack(len(snapshot.Events))
				for _, task := range response.Tasks {
					if err := verifyTask(task, client.serverKey, time.Now()); err != nil {
						log.Printf("rejected task %q: %v", task.ID, err)
						continue
					}
					taskCtx, taskCancel := context.WithTimeout(ctx, time.Duration(config.CommandTimeout))
					result := registry.Execute(taskCtx, task)
					taskCancel()
					_ = queue.Enqueue(map[string]any{"type": "action_result", "result": result})
				}
			} else {
				log.Printf("controller verified pending identity; waiting for activation")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type cliDependencies struct {
	buildInfo  func() (BuildInfo, error)
	loadConfig func(string) (Config, error)
	run        func(Config, BuildInfo) error
}

func executeCLI(
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	dependencies cliDependencies,
) int {
	if len(arguments) == 1 && (arguments[0] == "version" || arguments[0] == "--version") {
		info, err := dependencies.buildInfo()
		if err != nil {
			fmt.Fprintf(stderr, "version error: %v\n", err)
			return 1
		}
		printBuildInfo(stdout, info)
		return 0
	}
	if len(arguments) > 0 && arguments[0] == "bootstrap" {
		return executeBootstrapCLI(arguments[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("guardian-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String(
		"config",
		"/etc/vps-guardian-agent/config.json",
		"absolute config path",
	)
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	build, err := dependencies.buildInfo()
	if err != nil {
		fmt.Fprintf(stderr, "build metadata error: %v\n", err)
		return 1
	}
	config, err := dependencies.loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 1
	}
	if err := dependencies.run(config, build); err != nil {
		fmt.Fprintf(stderr, "agent stopped: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(executeCLI(
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		cliDependencies{
			buildInfo:  currentBuildInfo,
			loadConfig: loadConfig,
			run:        run,
		},
	))
}
