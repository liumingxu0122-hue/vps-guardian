package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testRenewalMaterial(t *testing.T, root string, agentID string, generation int) (Config, renewalResponse, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Agent Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(generation + 100)),
		Subject:               pkix.Name{CommonName: "renewed-agent"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(12 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  mustParseURIs(t, "spiffe://vps-guardian/agents/"+agentID),
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &tlsKey.PublicKey, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingDER, err := x509.MarshalPKCS8PrivateKey(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(root, "agent-ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	response := renewalResponse{
		Identity: renewalIdentity{
			Generation:             generation,
			CertificateFingerprint: certificateFingerprint(leaf),
		},
		CertificatePEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		CABundlePEM:          string(caPEM),
		CertificateExpiresAt: leaf.NotAfter,
	}
	return Config{AgentID: agentID, AgentCAFile: caPath}, response,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signingDER})
}

func mustParseURIs(t *testing.T, values ...string) []*url.URL {
	t.Helper()
	result := make([]*url.URL, 0, len(values))
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, parsed)
	}
	return result
}

func TestBuildRenewalRequestCreatesCSRAndNewKeyProof(t *testing.T) {
	payload, privateKeyPEM, signingKeyPEM, err := buildRenewalRequest(4)
	if err != nil {
		t.Fatal(err)
	}
	csrBlock, _ := pem.Decode([]byte(payload.CSRPEM))
	if csrBlock == nil {
		t.Fatal("CSR is not PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR signature is invalid: %v", err)
	}
	keyBlock, _ := pem.Decode(privateKeyPEM)
	if keyBlock == nil {
		t.Fatal("TLS key is not PEM encoded")
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatal(err)
	}
	signingBlock, _ := pem.Decode(signingKeyPEM)
	parsedSigningKey, err := x509.ParsePKCS8PrivateKey(signingBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := parsedSigningKey.(ed25519.PrivateKey)
	proof, err := base64.StdEncoding.DecodeString(payload.SigningKeyProof)
	if err != nil || !ed25519.Verify(signingKey.Public().(ed25519.PublicKey), []byte(payload.CSRPEM), proof) {
		t.Fatal("new signing key proof is invalid")
	}
	if payload.ExpectedVersion != 4 || payload.RotationID == "" {
		t.Fatal("renewal metadata is incomplete")
	}
}

func TestValidateAndAtomicallyActivateRenewedIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic-link activation is exercised on the Linux CI target")
	}
	root := t.TempDir()
	identityRoot := filepath.Join(root, "identities")
	oldGeneration := filepath.Join(identityRoot, "generation-1")
	if err := os.MkdirAll(oldGeneration, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("generation-1", filepath.Join(identityRoot, "current")); err != nil {
		t.Fatal(err)
	}
	config, response, privateKeyPEM, signingKeyPEM := testRenewalMaterial(t, root, "agent-test", 2)
	config.CertificateFile = filepath.Join(identityRoot, "current", "agent.crt")
	config.PrivateKeyFile = filepath.Join(identityRoot, "current", "agent.key")
	config.SigningKeyFile = filepath.Join(identityRoot, "current", "signing-ed25519.pem")
	if err := validateRenewedIdentity(config, response, privateKeyPEM); err != nil {
		t.Fatal(err)
	}
	if err := atomicActivateIdentity(config, response, privateKeyPEM, signingKeyPEM); err != nil {
		t.Fatal(err)
	}
	currentTarget, err := os.Readlink(filepath.Join(identityRoot, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if currentTarget == "generation-1" {
		t.Fatal("current identity link was not advanced")
	}
	if _, err := os.Stat(oldGeneration); err != nil {
		t.Fatal("previous identity generation was not retained")
	}
	if _, err := os.Stat(config.CertificateFile); err != nil {
		t.Fatal("renewed certificate is not available through current identity link")
	}
}
