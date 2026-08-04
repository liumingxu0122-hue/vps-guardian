package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type enrollmentTLSFixture struct {
	certificate tls.Certificate
	rootPEM     []byte
}

func enrollmentTLSChain(
	t *testing.T,
	hostname string,
	includeIntermediate bool,
	notBefore time.Time,
	notAfter time.Time,
	serverAuth bool,
) enrollmentTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Enrollment HTTPS Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		rootPublic,
		rootPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePublic, intermediatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Enrollment HTTPS Test Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediateDER, err := x509.CreateCertificate(
		rand.Reader,
		intermediateTemplate,
		root,
		intermediatePublic,
		rootPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if serverAuth {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(102),
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		intermediate,
		leafPublic,
		intermediatePrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{leafDER}
	if includeIntermediate {
		chain = append(chain, intermediateDER)
	}
	return enrollmentTLSFixture{
		certificate: tls.Certificate{Certificate: chain, PrivateKey: leafPrivate},
		rootPEM: pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: rootDER},
		),
	}
}

func requestEnrollmentTLS(
	t *testing.T,
	fixture enrollmentTLSFixture,
	caBundle []byte,
	hostname string,
	handler http.Handler,
) (*http.Response, error) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{fixture.certificate},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "enrollment-https-ca-bundle.pem")
	if err := os.WriteFile(caPath, caBundle, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := bootstrapHTTPClient(caPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	address := strings.TrimPrefix(server.URL, "https://")
	transport.DialContext = func(
		ctx context.Context,
		network string,
		_ string,
	) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	request, err := http.NewRequest(http.MethodPost, "https://"+hostname+"/bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Enrollment-Token", "test-token-that-must-never-follow-a-redirect")
	return client.Do(request)
}

func TestEnrollmentHTTPSTrustValidatesFullChainAndPurpose(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name                string
		hostname            string
		requestedHostname   string
		includeIntermediate bool
		notBefore           time.Time
		notAfter            time.Time
		serverAuth          bool
		wrongRoot           bool
		wantSuccess         bool
	}{
		{"full chain", "enrollment.example.test", "enrollment.example.test", true, now.Add(-time.Minute), now.Add(time.Hour), true, false, true},
		{"missing intermediate", "enrollment.example.test", "enrollment.example.test", false, now.Add(-time.Minute), now.Add(time.Hour), true, false, false},
		{"wrong root", "enrollment.example.test", "enrollment.example.test", true, now.Add(-time.Minute), now.Add(time.Hour), true, true, false},
		{"SAN mismatch", "other.example.test", "enrollment.example.test", true, now.Add(-time.Minute), now.Add(time.Hour), true, false, false},
		{"expired", "enrollment.example.test", "enrollment.example.test", true, now.Add(-2 * time.Hour), now.Add(-time.Hour), true, false, false},
		{"missing serverAuth", "enrollment.example.test", "enrollment.example.test", true, now.Add(-time.Minute), now.Add(time.Hour), false, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := enrollmentTLSChain(
				t,
				test.hostname,
				test.includeIntermediate,
				test.notBefore,
				test.notAfter,
				test.serverAuth,
			)
			roots := fixture.rootPEM
			if test.wrongRoot {
				roots = enrollmentTLSChain(
					t,
					"unused.example.test",
					true,
					now.Add(-time.Minute),
					now.Add(time.Hour),
					true,
				).rootPEM
			}
			response, err := requestEnrollmentTLS(
				t,
				fixture,
				roots,
				test.requestedHostname,
				http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusNoContent)
				}),
			)
			if test.wantSuccess {
				if err != nil || response.StatusCode != http.StatusNoContent {
					t.Fatalf("valid Enrollment HTTPS chain rejected: %v", err)
				}
				_ = response.Body.Close()
				return
			}
			if err == nil {
				_ = response.Body.Close()
				t.Fatal("invalid Enrollment HTTPS chain was accepted")
			}
		})
	}
}

func TestEnrollmentHTTPSCARotationAcceptsEitherPinnedRoot(t *testing.T) {
	now := time.Now().UTC()
	oldRoot := enrollmentTLSChain(
		t,
		"old.example.test",
		true,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		true,
	)
	current := enrollmentTLSChain(
		t,
		"enrollment.example.test",
		true,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		true,
	)
	response, err := requestEnrollmentTLS(
		t,
		current,
		append(oldRoot.rootPEM, current.rootPEM...),
		"enrollment.example.test",
		http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
		}),
	)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("dual-root transition rejected current root: %v", err)
	}
	_ = response.Body.Close()
}

func TestEnrollmentTokenRequestNeverFollowsRedirectStatus(t *testing.T) {
	now := time.Now().UTC()
	fixture := enrollmentTLSChain(
		t,
		"enrollment.example.test",
		true,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		true,
	)
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			response, err := requestEnrollmentTLS(
				t,
				fixture,
				fixture.rootPEM,
				"enrollment.example.test",
				http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					requests.Add(1)
					if request.Header.Get("X-Enrollment-Token") == "" {
						t.Error("Enrollment token header was missing")
					}
					writer.Header().Set("Location", "https://redirect.example.test/steal")
					writer.WriteHeader(status)
				}),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != status || requests.Load() != 1 {
				t.Fatalf("redirect status was followed: status=%d requests=%d", response.StatusCode, requests.Load())
			}
		})
	}
}

func TestBootstrapRejectsWrongAgentMTLSCAAfterHTTPSTrustSucceeds(t *testing.T) {
	request, privateKeyPEM, _, err := buildBootstrapRequest(
		bootstrapTestHostID,
		"0.4.0-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	response := bootstrapTestResponse(t, request)
	now := time.Now().UTC()
	response.AgentMTLSCABundlePEM = string(enrollmentTLSChain(
		t,
		"unrelated.example.test",
		true,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		true,
	).rootPEM)
	if err := validateBootstrapResponse(response, request, privateKeyPEM); err == nil {
		t.Fatal("Agent identity signed by a different mTLS CA was accepted")
	}
}

func TestWrongEnrollmentHTTPSCARejectsBeforeHTTPHandler(t *testing.T) {
	now := time.Now().UTC()
	fixture := enrollmentTLSChain(
		t,
		"enrollment.example.test",
		true,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		true,
	)
	wrong := enrollmentTLSChain(
		t,
		"wrong.example.test",
		true,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		true,
	)
	var requests atomic.Int32
	response, err := requestEnrollmentTLS(
		t,
		fixture,
		wrong.rootPEM,
		"enrollment.example.test",
		http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		}),
	)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || requests.Load() != 0 {
		t.Fatalf("wrong Enrollment HTTPS root reached HTTP handler: err=%v requests=%d", err, requests.Load())
	}
}

func TestEnrollmentGatewayURLRemainsCredentialFree(t *testing.T) {
	parsed, err := url.Parse("https://enrollment.example.test")
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatal("fixture Enrollment Gateway URL is not credential-free")
	}
}
