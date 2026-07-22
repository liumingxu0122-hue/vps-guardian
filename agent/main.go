package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(config Config) error {
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
		snapshot, err := collectSnapshot(config, queue, pendingChecks, registry.RestartCount())
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

func main() {
	configPath := flag.String("config", "/etc/vps-guardian-agent/config.json", "absolute config path")
	flag.Parse()
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	if err := run(config); err != nil {
		log.Fatalf("agent stopped: %v", err)
	}
}
