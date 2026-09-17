package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A secret file that does not exist is created, once, and then used.
//
// Turning proof on used to take a flag and a separate command to make the
// secret; a container starting against an empty volume had neither.
func TestAMissingSecretIsCreatedAndThenKept(t *testing.T) {
	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })

	path := filepath.Join(t.TempDir(), "secret")
	if err := createSecret(path); err != nil {
		t.Fatal(err)
	}
	scope, err := verificationScope(path, "")
	if err != nil || scope == nil {
		t.Fatalf("a missing secret was not created: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(first)))
	if err != nil || len(raw) != 32 {
		t.Errorf("the secret is not 32 random bytes in base64: %q", first)
	}
	if !strings.Contains(said.String(), "new verification secret") || strings.Contains(said.String(), string(first[:8])) {
		t.Errorf("the creation was not said, or the secret was: %q", said.String())
	}
	// Windows keeps no Unix mode to read, so this half runs where CI runs, on
	// Linux; a sabotage widening the mode escapes a Windows run and nothing else.
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("the secret is readable beyond its owner: %v", info.Mode().Perm())
		}
	}

	// Started again, the same secret, and nothing announced.
	said.Reset()
	if err := createSecret(path); err != nil {
		t.Fatal(err)
	}
	again, err := verificationScope(path, "")
	if err != nil || string(again.Secret) != string(scope.Secret) {
		t.Errorf("a second start did not keep the secret: %v", err)
	}
	if said.Len() != 0 {
		t.Errorf("an existing secret was announced as new: %q", said.String())
	}

	// A file that exists and is too short is still refused, not replaced.
	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createSecret(short); err != nil {
		t.Fatal(err)
	}
	if _, err := verificationScope(short, ""); err == nil {
		t.Error("a short secret was accepted")
	}
	if b, _ := os.ReadFile(short); string(b) != "tiny" {
		t.Error("an existing secret was overwritten")
	}

	// And a directory that cannot hold one stops the start.
	if err := createSecret(filepath.Join(t.TempDir(), "missing", "secret")); err == nil {
		t.Error("a secret that could not be created was not an error")
	}
}

// The secret is created where the service starts, and not by -version, which
// is a question.
func TestTheSecretIsCreatedByStartingAndNotByAsking(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")
	create := strings.Index(source, "createSecret(*verifySecretFile)")
	version := strings.Index(source, `reach(scope != nil))`)
	scope := strings.LastIndex(source, "verificationScope(*verifySecretFile, *resolver)")
	if create < 0 || scope < 0 || create > scope {
		t.Error("the service reads its secret before creating it")
	}
	if version < 0 || create < version {
		t.Error("-version can create a secret")
	}
}

// A service that scans anything listens on loopback, or says -open.
func TestAnOpenServiceStaysOnLoopback(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080", "127.1.2.3:9"} {
		if err := openAllowed(listen, false, false); err != nil {
			t.Errorf("%s was refused: %v", listen, err)
		}
	}
	for _, listen := range []string{"0.0.0.0:8443", ":8443", "[::]:8443", "192.0.2.10:443", "scanner.example:443"} {
		if err := openAllowed(listen, false, false); err == nil {
			t.Errorf("%s, with no proof required, was allowed", listen)
		}
		if err := openAllowed(listen, true, false); err != nil {
			t.Errorf("%s with proof required was refused: %v", listen, err)
		}
		if err := openAllowed(listen, false, true); err != nil {
			t.Errorf("%s with -open was refused: %v", listen, err)
		}
	}

	// Asked before anything listens.
	source := repoFile(t, "cmd/porchd/main.go")
	check := strings.Index(source, "openAllowed(*listen, scope != nil || demo.Enabled, *allowOpen)")
	serve := strings.Index(source, `net.Listen("tcp", *listen)`)
	if check < 0 || serve < 0 || check > serve {
		t.Error("the open-service check is not made before listening")
	}
}
