package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sha256String(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
