package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type bootstrapRequest struct {
	HostID           string `json:"host_id"`
	CSRPEM           string `json:"csr_pem"`
	SigningPublicKey string `json:"signing_public_key"`
	SigningKeyProof  string `json:"signing_key_proof"`
	Version          string `json:"version"`
}

type bootstrapResponse struct {
	AgentID                 string    `json:"agent_id"`
	HostID                  string    `json:"host_id"`
	CertificatePEM          string    `json:"certificate_pem"`
	AgentMTLSCABundlePEM    string    `json:"agent_mtls_ca_bundle_pem"`
	CertificateSerial       string    `json:"certificate_serial"`
	CertificateExpiresAt    time.Time `json:"certificate_expires_at"`
	AgentGatewayEndpoint    string    `json:"agent_gateway_endpoint"`
	EnrollmentProgressToken string    `json:"enrollment_progress_token"`
	HeartbeatIntervalSecond int       `json:"heartbeat_interval_seconds"`
}

type bootstrapMetadata struct {
	AgentID              string    `json:"agent_id"`
	HostID               string    `json:"host_id"`
	AgentGatewayEndpoint string    `json:"agent_gateway_endpoint"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
}

var bootstrapTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{32,512}$`)
var bootstrapHostIDPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
)

func buildBootstrapRequest(hostID, version string) (bootstrapRequest, []byte, []byte, error) {
	if !bootstrapHostIDPattern.MatchString(hostID) {
		return bootstrapRequest{}, nil, nil, errors.New("host ID must be a UUID")
	}
	if version == "" || len(version) > 64 {
		return bootstrapRequest{}, nil, nil, errors.New("Agent version is invalid")
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return bootstrapRequest{}, nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "vps-guardian-agent-bootstrap"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, tlsKey)
	if err != nil {
		return bootstrapRequest{}, nil, nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	publicSigningKey, privateSigningKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return bootstrapRequest{}, nil, nil, err
	}
	tlsKeyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return bootstrapRequest{}, nil, nil, err
	}
	signingKeyDER, err := x509.MarshalPKCS8PrivateKey(privateSigningKey)
	if err != nil {
		return bootstrapRequest{}, nil, nil, err
	}
	return bootstrapRequest{
			HostID:           hostID,
			CSRPEM:           string(csrPEM),
			SigningPublicKey: base64.StdEncoding.EncodeToString(publicSigningKey),
			SigningKeyProof:  base64.StdEncoding.EncodeToString(ed25519.Sign(privateSigningKey, csrPEM)),
			Version:          version,
		}, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsKeyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signingKeyDER}), nil
}

func readBootstrapToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("enrollment token file path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("enrollment token file is missing or unsafe")
	}
	if info.Size() < 32 || info.Size() > 513 {
		return "", errors.New("enrollment token file has an invalid size")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("enrollment token file permissions are unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("enrollment token file is unreadable")
	}
	value := strings.TrimSuffix(string(data), "\n")
	value = strings.TrimSuffix(value, "\r")
	if !bootstrapTokenPattern.MatchString(value) {
		return "", errors.New("enrollment token file has an invalid value")
	}
	return value, nil
}

func bootstrapHTTPClient(enrollmentHTTPSCABundleFile string, timeout time.Duration) (*http.Client, error) {
	if !filepath.IsAbs(enrollmentHTTPSCABundleFile) {
		return nil, errors.New("Enrollment HTTPS CA bundle path must be absolute")
	}
	if timeout <= 0 || timeout > 5*time.Minute {
		return nil, errors.New("Controller request timeout is invalid")
	}
	caData, err := os.ReadFile(enrollmentHTTPSCABundleFile)
	if err != nil {
		return nil, errors.New("Enrollment HTTPS CA bundle is unreadable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caData) {
		return nil, errors.New("Enrollment HTTPS CA bundle is invalid")
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		}},
	}, nil
}

func validateBootstrapResponse(
	response bootstrapResponse,
	request bootstrapRequest,
	privateKeyPEM []byte,
) error {
	if response.AgentID == "" || response.HostID != request.HostID ||
		response.AgentGatewayEndpoint == "" || response.CertificateExpiresAt.IsZero() {
		return errors.New("bootstrap response identity is invalid")
	}
	if !bootstrapTokenPattern.MatchString(response.EnrollmentProgressToken) {
		return errors.New("bootstrap response progress credential is invalid")
	}
	if !bootstrapHostIDPattern.MatchString(response.AgentID) {
		return errors.New("bootstrap response Agent ID is invalid")
	}
	gateway, err := url.Parse(response.AgentGatewayEndpoint)
	if err != nil || gateway.Scheme != "https" || gateway.Host == "" ||
		gateway.User != nil || gateway.RawQuery != "" || gateway.Fragment != "" {
		return errors.New("bootstrap response gateway is invalid")
	}
	if !response.CertificateExpiresAt.After(time.Now()) {
		return errors.New("bootstrap response certificate is expired")
	}
	keyPair, err := tls.X509KeyPair([]byte(response.CertificatePEM), privateKeyPEM)
	if err != nil || len(keyPair.Certificate) != 1 {
		return errors.New("bootstrap certificate does not match the local private key")
	}
	certificate, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return errors.New("bootstrap certificate is invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(response.AgentMTLSCABundlePEM)) {
		return errors.New("bootstrap Agent mTLS CA bundle is invalid")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}); err != nil {
		return errors.New("bootstrap certificate is not signed by the returned Agent mTLS CA")
	}
	expectedURI := "spiffe://vps-guardian/agents/" + response.AgentID
	for _, uri := range certificate.URIs {
		if uri.String() == expectedURI {
			return nil
		}
	}
	return errors.New("bootstrap certificate is not bound to the returned Agent identity")
}

func writeBootstrapIdentity(
	outputDirectory string,
	response bootstrapResponse,
	privateKeyPEM, signingKeyPEM []byte,
) error {
	if !filepath.IsAbs(outputDirectory) {
		return errors.New("bootstrap output directory must be absolute")
	}
	parent := filepath.Dir(outputDirectory)
	temporary, err := os.MkdirTemp(parent, ".guardian-bootstrap-")
	if err != nil {
		return err
	}
	keep := true
	defer func() {
		if keep {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	metadata, err := json.Marshal(bootstrapMetadata{
		AgentID:              response.AgentID,
		HostID:               response.HostID,
		AgentGatewayEndpoint: response.AgentGatewayEndpoint,
		CertificateExpiresAt: response.CertificateExpiresAt,
	})
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"agent.key", privateKeyPEM, 0o600},
		{"agent.crt", []byte(response.CertificatePEM), 0o644},
		{"agent-mtls-ca-bundle.pem", []byte(response.AgentMTLSCABundlePEM), 0o644},
		{"signing-ed25519.pem", signingKeyPEM, 0o600},
		{"bootstrap.json", append(metadata, '\n'), 0o600},
		{"enrollment-progress-token", []byte(response.EnrollmentProgressToken), 0o600},
	}
	for _, item := range files {
		if err := os.WriteFile(filepath.Join(temporary, item.name), item.data, item.mode); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(outputDirectory); !os.IsNotExist(err) {
		return errors.New("bootstrap output directory already exists")
	}
	if err := os.Rename(temporary, outputDirectory); err != nil {
		return err
	}
	keep = false
	return nil
}

func runBootstrap(
	ctx context.Context,
	controllerURL, hostID, tokenFile, enrollmentHTTPSCABundleFile, outputDirectory, version string,
	timeout time.Duration,
) error {
	parsed, err := url.Parse(controllerURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("Controller URL must be a credential-free HTTPS URL")
	}
	token, err := readBootstrapToken(tokenFile)
	if err != nil {
		return err
	}
	payload, privateKeyPEM, signingKeyPEM, err := buildBootstrapRequest(hostID, version)
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client, err := bootstrapHTTPClient(enrollmentHTTPSCABundleFile, timeout)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(controllerURL, "/") + "/api/v1/agents/bootstrap"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Enrollment-Token", token)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Controller enrollment request failed")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return errors.New("Controller enrollment response is unreadable")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Controller enrollment returned status %d", response.StatusCode)
	}
	var decoded bootstrapResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return errors.New("Controller enrollment response is invalid")
	}
	if err := validateBootstrapResponse(decoded, payload, privateKeyPEM); err != nil {
		return err
	}
	return writeBootstrapIdentity(outputDirectory, decoded, privateKeyPEM, signingKeyPEM)
}

func executeBootstrapCLI(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	controllerURL := flags.String("controller-url", "", "Controller HTTPS origin")
	hostID := flags.String("host-id", "", "pre-created Host UUID")
	tokenFile := flags.String("token-file", "", "one-time enrollment token file")
	enrollmentHTTPSCABundleFile := flags.String(
		"enrollment-https-ca-bundle-file",
		"",
		"CA bundle used only for Enrollment HTTPS transport",
	)
	outputDirectory := flags.String("output-dir", "", "new identity output directory")
	version := flags.String("agent-version", "", "immutable Agent version")
	timeout := flags.Duration("timeout", 45*time.Second, "bootstrap request timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := runBootstrap(
		context.Background(),
		*controllerURL,
		*hostID,
		*tokenFile,
		*enrollmentHTTPSCABundleFile,
		*outputDirectory,
		*version,
		*timeout,
	); err != nil {
		fmt.Fprintf(stderr, "bootstrap failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "Agent identity created locally")
	return 0
}
