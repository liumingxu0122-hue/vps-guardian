package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const bootstrapTestHostID = "19ca9b96-a220-44ce-b37d-e27ca4a77701"
const bootstrapTestAgentID = "f791d98c-0f7d-4b45-98cd-d8002e27c0b8"

func bootstrapTestResponse(
	t *testing.T,
	request bootstrapRequest,
) bootstrapResponse {
	t.Helper()
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	if csrBlock == nil {
		t.Fatal("CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR is invalid: %v", err)
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bootstrap Test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(
		rand.Reader,
		caTemplate,
		caTemplate,
		caPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	spiffeURI, err := url.Parse("spiffe://vps-guardian/agents/" + bootstrapTestAgentID)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "VPS Guardian Agent"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(12 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{spiffeURI},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		caCertificate,
		csr.PublicKey,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrapResponse{
		AgentID:                 bootstrapTestAgentID,
		HostID:                  request.HostID,
		CertificatePEM:          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		CABundlePEM:             string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		CertificateExpiresAt:    leafTemplate.NotAfter,
		AgentGatewayEndpoint:    "https://agents.example.test",
		EnrollmentProgressToken: "test-progress-token-value-that-is-long-enough",
	}
}

func TestBuildBootstrapRequestCreatesKeysLocallyAndProvesSigningKey(t *testing.T) {
	request, privateKeyPEM, signingKeyPEM, err := buildBootstrapRequest(
		bootstrapTestHostID,
		"0.4.0-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyPEM) == 0 || len(signingKeyPEM) == 0 {
		t.Fatal("local private key material was not returned")
	}
	signingBlock, _ := pem.Decode(signingKeyPEM)
	if signingBlock == nil {
		t.Fatal("signing key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(signingBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := parsed.(ed25519.PrivateKey)
	proof, err := base64.StdEncoding.DecodeString(request.SigningKeyProof)
	if err != nil || !ed25519.Verify(
		signingKey.Public().(ed25519.PublicKey),
		[]byte(request.CSRPEM),
		proof,
	) {
		t.Fatal("signing-key proof is invalid")
	}
}

func TestReadBootstrapTokenRejectsRelativeAndSymlinkPaths(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	token := "test-token-value-that-is-at-least-thirty-two-bytes"
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if actual, err := readBootstrapToken(tokenPath); err != nil || actual != token {
		t.Fatalf("secure token file rejected: %v", err)
	}
	if _, err := readBootstrapToken("relative-token"); err == nil {
		t.Fatal("relative token path was accepted")
	}
	link := filepath.Join(root, "token-link")
	if err := os.Symlink(tokenPath, link); err == nil {
		if _, err := readBootstrapToken(link); err == nil {
			t.Fatal("symlink token file was accepted")
		}
	}
}

func TestValidateAndWriteBootstrapIdentityAtomically(t *testing.T) {
	request, privateKeyPEM, signingKeyPEM, err := buildBootstrapRequest(
		bootstrapTestHostID,
		"0.4.0-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	response := bootstrapTestResponse(t, request)
	if err := validateBootstrapResponse(response, request, privateKeyPEM); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "identity")
	if err := writeBootstrapIdentity(output, response, privateKeyPEM, signingKeyPEM); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"agent.key",
		"agent.crt",
		"agent-ca.crt",
		"signing-ed25519.pem",
		"bootstrap.json",
		"enrollment-progress-token",
	} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatalf("bootstrap output %s is missing: %v", name, err)
		}
	}
	if err := writeBootstrapIdentity(output, response, privateKeyPEM, signingKeyPEM); err == nil {
		t.Fatal("existing identity directory was overwritten")
	}
}

func TestValidateBootstrapResponseRejectsUnsafeGatewayAndWrongHost(t *testing.T) {
	request, privateKeyPEM, _, err := buildBootstrapRequest(
		bootstrapTestHostID,
		"0.4.0-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	response := bootstrapTestResponse(t, request)
	response.AgentGatewayEndpoint = "https://user@example.test?token=unsafe"
	if err := validateBootstrapResponse(response, request, privateKeyPEM); err == nil {
		t.Fatal("credential-bearing gateway was accepted")
	}
	response = bootstrapTestResponse(t, request)
	response.HostID = "bd4bc42f-6d62-469c-8b64-580270da7c98"
	if err := validateBootstrapResponse(response, request, privateKeyPEM); err == nil {
		t.Fatal("wrong Host binding was accepted")
	}
}

func TestBootstrapClientRefusesRedirects(t *testing.T) {
	request, _, _, err := buildBootstrapRequest(bootstrapTestHostID, "0.4.0-test")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "controller-ca.pem")
	if err := os.WriteFile(
		caPath,
		[]byte(bootstrapTestResponse(t, request).CABundlePEM),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	client, err := bootstrapHTTPClient(caPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	redirectRequest, _ := http.NewRequest(http.MethodGet, "https://other.example.test", nil)
	if err := client.CheckRedirect(redirectRequest, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect was not refused: %v", err)
	}
}
