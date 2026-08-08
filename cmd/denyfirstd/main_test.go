package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/httpapi"
)

// WriteTimeout covers the entire exchange. Set at or below the scan budget it
// truncates the response mid-encode, and the user sees a cut-off body with no
// explanation. The margin is what keeps that from happening, so it has to stay
// positive whatever the defaults become.
func TestWriteMarginExceedsTheScanBudget(t *testing.T) {
	if writeMargin <= 0 {
		t.Fatalf("writeMargin = %v; a response needs time to be written after the scan ends", writeMargin)
	}

	write := httpapi.DefaultRequestTimeout + writeMargin
	if write <= httpapi.DefaultRequestTimeout {
		t.Errorf("WriteTimeout %v does not exceed the scan budget %v", write, httpapi.DefaultRequestTimeout)
	}
}

// A shutdown that ends before an in-flight scan does truncates its response,
// which defeats the purpose of shutting down gracefully.
func TestShutdownGraceOutlastsAScan(t *testing.T) {
	if shutdownGrace <= httpapi.DefaultRequestTimeout {
		t.Errorf("shutdownGrace %v does not exceed the scan budget %v; a clean stop would cut responses off",
			shutdownGrace, httpapi.DefaultRequestTimeout)
	}
}

// The request body is one JSON field. A megabyte of headers is not something
// this endpoint has any use for.
func TestHeaderLimitIsModest(t *testing.T) {
	if maxHeaderBytes > 64<<10 {
		t.Errorf("maxHeaderBytes = %d, larger than this endpoint can justify", maxHeaderBytes)
	}
	if maxHeaderBytes < 4<<10 {
		t.Errorf("maxHeaderBytes = %d, too small for ordinary browser headers", maxHeaderBytes)
	}
}

func writeKeyPair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{name},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("creating %s: %v", certPath, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}
	certOut.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("creating %s: %v", keyPath, err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	keyOut.Close()

	return certPath, keyPath
}

func subjectOf(t *testing.T, cert *tls.Certificate) string {
	t.Helper()

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the served certificate: %v", err)
	}
	return parsed.Subject.CommonName
}

// Certificates now last weeks and are renewed by a timer. A process that
// reads them once at startup goes on presenting an expired certificate until
// somebody notices.
func TestCertificateIsReloadedAfterRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir, "first.test")

	r, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	served, err := r.get(nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := subjectOf(t, served); got != "first.test" {
		t.Fatalf("subject = %q, want first.test", got)
	}

	// Stand in for a renewal tool rewriting the files.
	writeKeyPair(t, dir, "renewed.test")

	// The stat interval is there so a busy server does not stat twice per
	// handshake. Reaching past it is what a real renewal would do.
	r.mu.Lock()
	r.lastStat = time.Now().Add(-2 * statInterval)
	r.mu.Unlock()

	served, err = r.get(nil)
	if err != nil {
		t.Fatalf("get after renewal: %v", err)
	}
	if got := subjectOf(t, served); got != "renewed.test" {
		t.Errorf("subject = %q after renewal, want renewed.test", got)
	}
}

// A renewal that writes a partial file must not take the service down. The
// certificate that worked a moment ago is better than refusing every
// handshake.
func TestBrokenRenewalKeepsThePreviousCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir, "good.test")

	r, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0o600); err != nil {
		t.Fatalf("writing a partial certificate: %v", err)
	}

	r.mu.Lock()
	r.lastStat = time.Now().Add(-2 * statInterval)
	r.mu.Unlock()

	served, err := r.get(nil)
	if err != nil {
		t.Fatalf("get returned an error instead of the previous certificate: %v", err)
	}
	if served == nil {
		t.Fatal("no certificate was served after a failed reload")
	}
	if got := subjectOf(t, served); got != "good.test" {
		t.Errorf("subject = %q, want the previous certificate good.test", got)
	}
}

func TestMissingCertificateIsAStartupError(t *testing.T) {
	dir := t.TempDir()
	if _, err := newCertReloader(filepath.Join(dir, "absent.pem"), filepath.Join(dir, "absent.key")); err == nil {
		t.Error("newCertReloader accepted paths that do not exist")
	}
}

// The default http.Server logger writes lines such as "http: panic serving
// 203.0.113.7" to standard error. That is a client address in a log file,
// which invariant P1 forbids, and it would appear without any code here ever
// writing it.
func TestSilentErrorLogDiscards(t *testing.T) {
	logger := httpapi.SilentErrorLog()
	if logger == nil {
		t.Fatal("SilentErrorLog returned nil; http.Server would fall back to its default")
	}
	if logger.Writer() != io.Discard {
		t.Error("SilentErrorLog does not discard; a promise that depends on a library default is not a promise")
	}

	logger.Printf("http: panic serving 203.0.113.7:5000")
}
