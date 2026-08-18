package web

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// The key a reporter encrypts to is reachable, and it is a key.
func TestPGPKeyIsServed(t *testing.T) {
	w := get(t, PGPKeyPath)

	if w.Code != http.StatusOK {
		t.Fatalf("GET %s returned %d, want 200", PGPKeyPath, w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", got)
	}

	body := w.Body.String()
	for _, required := range []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"-----END PGP PUBLIC KEY BLOCK-----",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("the served file does not contain %q", required)
		}
	}

	// A private key served by accident is the worst outcome available here,
	// and it is one copied filename away.
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("the served file contains a private key block")
	}
}

// The fingerprint is written in three places and they have to agree.
//
// A key served from this domain and identified only by this domain proves
// nothing: whoever takes the domain serves their own key beside their own
// fingerprint, and a reporter encrypts an unpublished vulnerability straight
// to them. SECURITY.md lives on GitHub, behind a different account and
// different credentials, which is what makes it worth comparing against.
//
// Two sources that agree because nobody checks are one source written twice.
// This is the check.
func TestFingerprintAgreesAcrossSources(t *testing.T) {
	// Written without spaces in the constant and with them in the prose, so
	// both forms are compared against the same value.
	compact := strings.NewReplacer(" ", "", "\t", "").Replace

	if len(PGPFingerprint) != 40 {
		t.Fatalf("PGPFingerprint is %d characters, want 40 hex digits", len(PGPFingerprint))
	}
	for _, r := range PGPFingerprint {
		if !strings.ContainsRune("0123456789ABCDEF", r) {
			t.Fatalf("PGPFingerprint contains %q; want uppercase hex", r)
		}
	}

	securityTxt := get(t, SecurityTxtPath).Body.String()
	if !strings.Contains(compact(securityTxt), PGPFingerprint) {
		t.Errorf("security.txt does not carry the fingerprint %s", PGPFingerprint)
	}

	// The second source, read from disk because it is not served from here.
	// A test that only compared this file against itself would pass while the
	// two published fingerprints drifted apart.
	policy, err := os.ReadFile("../../SECURITY.md")
	if err != nil {
		t.Fatalf("reading SECURITY.md: %v", err)
	}
	if !strings.Contains(compact(string(policy)), PGPFingerprint) {
		t.Errorf("SECURITY.md does not carry the fingerprint %s; a reporter has nothing to compare against", PGPFingerprint)
	}
}

// security.txt has to point at the key, and at the copy this server actually
// serves rather than one that used to be somewhere else.
func TestSecurityTxtPointsAtTheKey(t *testing.T) {
	fields := securityTxtFields(t)

	encryption := fields["encryption"]
	if len(encryption) != 1 {
		t.Fatalf("%d Encryption fields, want exactly 1", len(encryption))
	}

	url := encryption[0]
	if !strings.HasPrefix(url, "https://") {
		t.Errorf("Encryption %q is not https", url)
	}
	if !strings.HasSuffix(url, PGPKeyPath) {
		t.Errorf("Encryption %q does not end at %s, which is where the key is served", url, PGPKeyPath)
	}
}
