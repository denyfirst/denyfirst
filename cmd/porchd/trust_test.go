package main

import (
	"strings"
	"testing"
)

// The service takes its store from internal/truststore, never from
// x509.SystemCertPool directly.
//
// On Windows and macOS a system pool sends every chain to the platform
// verifier, which fetches what a scanned certificate names outside safedial
// (audit A25). The pool this binary checks at start is the pool every scan is
// judged against, so it has to be the resolved one.
//
// Read from the source, for the reason the trust store test beside this gives:
// run() parses flags and binds a port.
func TestTheServiceTakesItsStoreFromTheResolver(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")
	if !strings.Contains(source, "roots, rootsErr := truststore.Resolve(nil)") {
		t.Error("run() does not take its trust store from truststore.Resolve")
	}
	if strings.Contains(source, "x509.SystemCertPool()") {
		t.Error("run() calls x509.SystemCertPool, whose pool the platform verifier answers for on Windows and macOS")
	}
}
