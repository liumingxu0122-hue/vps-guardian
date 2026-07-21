package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Task struct {
	ID         string            `json:"id"`
	Action     string            `json:"action"`
	Parameters map[string]string `json:"parameters"`
	Nonce      string            `json:"nonce"`
	ExpiresAt  int64             `json:"expires_at"`
	Signature  string            `json:"signature"`
}

type signedTask struct {
	ID         string            `json:"id"`
	Action     string            `json:"action"`
	Parameters map[string]string `json:"parameters"`
	Nonce      string            `json:"nonce"`
	ExpiresAt  int64             `json:"expires_at"`
}

func taskPayload(task Task) ([]byte, error) {
	return json.Marshal(signedTask{task.ID, task.Action, task.Parameters, task.Nonce, task.ExpiresAt})
}

func verifyTask(task Task, publicKey ed25519.PublicKey, now time.Time) error {
	if task.ID == "" || len(task.Nonce) < 16 {
		return errors.New("task identity is invalid")
	}
	if task.ExpiresAt < now.Unix() || task.ExpiresAt > now.Add(15*time.Minute).Unix() {
		return errors.New("task expiry is invalid")
	}
	payload, err := taskPayload(task)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(task.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("task signature is invalid")
	}
	return nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key must be PEM encoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return privateKey, nil
}

func signHeartbeat(agentID string, body []byte, privateKey ed25519.PrivateKey) (map[string]string, error) {
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	digest := sha256.Sum256(body)
	message := strings.Join([]string{agentID, timestamp, nonce, hex.EncodeToString(digest[:])}, "\n")
	signature := ed25519.Sign(privateKey, []byte(message))
	return map[string]string{
		"X-Agent-Timestamp": timestamp, "X-Agent-Nonce": nonce,
		"X-Agent-Signature": base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func decodeControllerPublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid controller public key")
	}
	return ed25519.PublicKey(decoded), nil
}
