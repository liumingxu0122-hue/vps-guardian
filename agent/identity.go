package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type renewalIdentity struct {
	Generation             int    `json:"generation"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
}

type renewalResponse struct {
	Identity             renewalIdentity `json:"identity"`
	CertificatePEM       string          `json:"certificate_pem"`
	CABundlePEM          string          `json:"ca_bundle_pem"`
	CertificateExpiresAt time.Time       `json:"certificate_expires_at"`
}

type renewalRequest struct {
	RotationID       string `json:"rotation_id"`
	ExpectedVersion  int    `json:"expected_version"`
	CSRPEM           string `json:"csr_pem"`
	SigningPublicKey string `json:"signing_public_key"`
	SigningKeyProof  string `json:"signing_key_proof"`
}

func certificateFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func buildRenewalRequest(expectedVersion int) (renewalRequest, []byte, []byte, error) {
	if expectedVersion < 1 {
		return renewalRequest{}, nil, nil, errors.New("identity version is invalid")
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return renewalRequest{}, nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "vps-guardian-agent-renewal"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, tlsKey)
	if err != nil {
		return renewalRequest{}, nil, nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return renewalRequest{}, nil, nil, err
	}
	tlsKeyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return renewalRequest{}, nil, nil, err
	}
	signingKeyDER, err := x509.MarshalPKCS8PrivateKey(signingKey)
	if err != nil {
		return renewalRequest{}, nil, nil, err
	}
	rotationID, err := randomUUID()
	if err != nil {
		return renewalRequest{}, nil, nil, err
	}
	return renewalRequest{
			RotationID:       rotationID,
			ExpectedVersion:  expectedVersion,
			CSRPEM:           string(csrPEM),
			SigningPublicKey: base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey)),
			SigningKeyProof:  base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, csrPEM)),
		}, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsKeyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signingKeyDER}), nil
}

func validateRenewedIdentity(config Config, response renewalResponse, privateKeyPEM []byte) error {
	keyPair, err := tls.X509KeyPair([]byte(response.CertificatePEM), privateKeyPEM)
	if err != nil {
		return fmt.Errorf("renewed certificate does not match its private key: %w", err)
	}
	if len(keyPair.Certificate) != 1 {
		return errors.New("renewed certificate response must contain exactly one certificate")
	}
	certificate, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}
	if certificateFingerprint(certificate) != strings.ToUpper(response.Identity.CertificateFingerprint) {
		return errors.New("renewed certificate fingerprint does not match the identity response")
	}
	if response.CertificateExpiresAt.IsZero() || !certificate.NotAfter.Equal(response.CertificateExpiresAt) {
		return errors.New("renewed certificate expiry does not match the response")
	}
	currentCA, err := os.ReadFile(config.AgentCAFile)
	if err != nil {
		return fmt.Errorf("read pinned Agent CA: %w", err)
	}
	pinnedRoots := x509.NewCertPool()
	returnedRoots := x509.NewCertPool()
	if !pinnedRoots.AppendCertsFromPEM(currentCA) ||
		!returnedRoots.AppendCertsFromPEM([]byte(response.CABundlePEM)) {
		return errors.New("Agent CA bundle is invalid")
	}
	verifyOptions := x509.VerifyOptions{Roots: pinnedRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := certificate.Verify(verifyOptions); err != nil {
		return fmt.Errorf("renewed certificate is not signed by the pinned Agent CA: %w", err)
	}
	verifyOptions.Roots = returnedRoots
	if _, err := certificate.Verify(verifyOptions); err != nil {
		return fmt.Errorf("renewed certificate does not verify against the returned CA: %w", err)
	}
	expectedURI := "spiffe://vps-guardian/agents/" + config.AgentID
	for _, uri := range certificate.URIs {
		if uri.String() == expectedURI {
			return nil
		}
	}
	return errors.New("renewed certificate is not bound to this Agent identity")
}

func atomicActivateIdentity(config Config, response renewalResponse, privateKeyPEM, signingKeyPEM []byte) error {
	currentDirectory := filepath.Dir(config.CertificateFile)
	if filepath.Base(currentDirectory) != "current" ||
		filepath.Dir(config.PrivateKeyFile) != currentDirectory ||
		filepath.Dir(config.SigningKeyFile) != currentDirectory {
		return errors.New("automatic renewal requires the generation-based identity layout")
	}
	identityRoot := filepath.Dir(currentDirectory)
	metadata, err := os.Lstat(currentDirectory)
	if err != nil || metadata.Mode()&os.ModeSymlink == 0 {
		return errors.New("current Agent identity is not an atomic generation link")
	}
	temporary, err := os.MkdirTemp(identityRoot, ".renewing-")
	if err != nil {
		return err
	}
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"agent.key", privateKeyPEM, 0o600},
		{"agent.crt", []byte(response.CertificatePEM), 0o644},
		{"signing-ed25519.pem", signingKeyPEM, 0o600},
	}
	for _, item := range files {
		if err := os.WriteFile(filepath.Join(temporary, item.name), item.data, item.mode); err != nil {
			return err
		}
	}
	finalName := fmt.Sprintf("generation-%d-%d", response.Identity.Generation, time.Now().Unix())
	finalDirectory := filepath.Join(identityRoot, finalName)
	if err := os.Rename(temporary, finalDirectory); err != nil {
		return err
	}
	keepTemporary = false
	nextLink := filepath.Join(identityRoot, fmt.Sprintf(".current-%d", time.Now().UnixNano()))
	if err := os.Symlink(finalName, nextLink); err != nil {
		return err
	}
	if err := os.Rename(nextLink, currentDirectory); err != nil {
		_ = os.Remove(nextLink)
		return err
	}
	return nil
}

func (c *ControllerClient) RenewCertificate(ctx context.Context, expectedVersion int) (*ControllerClient, error) {
	payload, privateKeyPEM, signingKeyPEM, err := buildRenewalRequest(expectedVersion)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	headers, err := signHeartbeat(c.config.AgentID, body, c.signingKey)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(c.config.ControllerURL, "/") + "/api/v1/agents/" + c.config.AgentID + "/certificate/renew"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Client-Cert-Fingerprint", c.config.CertificateFP)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	result, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(result.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	if result.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate renewal returned status %d", result.StatusCode)
	}
	var response renewalResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("decode certificate renewal response: %w", err)
	}
	if response.Identity.Generation != expectedVersion+1 {
		return nil, errors.New("certificate renewal returned an unexpected identity generation")
	}
	if err := validateRenewedIdentity(c.config, response, privateKeyPEM); err != nil {
		return nil, err
	}
	if err := atomicActivateIdentity(c.config, response, privateKeyPEM, signingKeyPEM); err != nil {
		return nil, err
	}
	return NewControllerClient(c.config)
}
