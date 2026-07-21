package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func signedTestTask(t *testing.T, privateKey ed25519.PrivateKey) Task {
	t.Helper()
	task := Task{ID: "task-1", Action: "local_health_check", Parameters: map[string]string{"target": "http://127.0.0.1:8080/health"}, Nonce: "nonce-that-is-long-enough", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	payload, err := taskPayload(task)
	if err != nil {
		t.Fatal(err)
	}
	task.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return task
}

func TestTaskSignatureAndExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	task := signedTestTask(t, privateKey)
	if err := verifyTask(task, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	task.Action = "restart_container"
	if err := verifyTask(task, publicKey, time.Now()); err == nil {
		t.Fatal("tampered task was accepted")
	}
	task = signedTestTask(t, privateKey)
	if err := verifyTask(task, publicKey, time.Now().Add(2*time.Minute)); err == nil {
		t.Fatal("expired task was accepted")
	}
}
