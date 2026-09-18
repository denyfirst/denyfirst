package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/access"
)

// A missing access file is created with a new password, which is said once
// and written nowhere; an existing one is left alone, because replacing it
// would make everything kept under its key unreadable.
func TestAMissingAccessFileIsCreatedAndItsPasswordSaidOnce(t *testing.T) {
	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })

	path := filepath.Join(t.TempDir(), "access")
	if err := createAccess(path); err != nil {
		t.Fatal(err)
	}
	password := regexp.MustCompile(`(?m)^    ([a-z2-7-]{38})$`).FindStringSubmatch(said.String())
	if password == nil {
		t.Fatalf("the new password was not said: %q", said.String())
	}
	if _, err := access.Unlock(path, password[1]); err != nil {
		t.Errorf("the password that was said does not open the file: %v", err)
	}
	// Nothing else was written beside it: the password is said, not saved.
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("creating the access file wrote %d files, want one", len(entries))
	}
	body, _ := os.ReadFile(path)
	if bytes.Contains(body, []byte(password[1])) {
		t.Error("the password was written into the access file")
	}
	if !strings.Contains(said.String(), "change it") || !strings.Contains(said.String(), "can no longer be read") {
		t.Errorf("the announcement does not say to change it, or what losing it costs: %q", said.String())
	}

	said.Reset()
	if err := createAccess(path); err != nil {
		t.Fatal(err)
	}
	if said.Len() != 0 {
		t.Errorf("an existing access file was announced as new: %q", said.String())
	}
	if _, err := access.Unlock(path, password[1]); err != nil {
		t.Error("starting again replaced the access file")
	}
}

// The gate is in front of the whole mux, so a route added later is behind it
// without anybody remembering to put it there, and the compose file turns it
// on.
func TestTheGateIsInFrontOfEverything(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")
	for _, want := range []string{
		"handler = gate.Wrap(root)",
		"Handler: handler,",
		`web.Configure(scope != nil, *resultsDir != "" || gate != nil, gate != nil)`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("main.go no longer contains %q", want)
		}
	}
	if strings.Contains(src, "Handler: root,") {
		t.Error("the server is handed the mux directly, around the gate")
	}

	compose := repoFile(t, "docker-compose.yml")
	if !strings.Contains(compose, `"-access-file"`) || !strings.Contains(compose, `"/data/access"`) {
		t.Error("the compose file does not put a password in front of the installation")
	}
}

// The command the sign-in page gives finds the password: it names the compose
// service, and greps for words the log line carries, and the password is on
// one of the two lines after them.
func TestTheSignInPageCommandFindsThePassword(t *testing.T) {
	page := repoFile(t, "internal/web/assets/login.html")
	const command = `docker compose logs porch | grep -A2 "password is"`
	if !strings.Contains(page, command) {
		t.Fatalf("the sign-in page no longer gives %q", command)
	}
	if !regexp.MustCompile(`(?m)^  porch:$`).MatchString(repoFile(t, "docker-compose.yml")) {
		t.Error("the compose file has no service called porch for the command to name")
	}

	var said bytes.Buffer
	previous := secretOut
	secretOut = &said
	t.Cleanup(func() { secretOut = previous })
	if err := createAccess(filepath.Join(t.TempDir(), "access")); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(said.String(), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "password is") {
			continue
		}
		for _, after := range lines[i+1 : min(i+3, len(lines))] {
			if regexp.MustCompile(`^    [a-z2-7-]{38}$`).MatchString(after) {
				return
			}
		}
	}
	t.Errorf("grep -A2 \"password is\" would not show the password in: %q", said.String())
}

// The history exists only behind a password: the vault, the reports kept in
// it and the routes that read it are made inside the one branch that makes
// the gate, and nowhere else.
func TestTheHistoryExistsOnlyBehindThePassword(t *testing.T) {
	src := repoFile(t, "cmd/porchd/main.go")
	const block = "\tif *accessFile != \"\" {\n" +
		"\t\tgate = access.NewGate(*accessFile, web.PublicPaths())\n" +
		"\t\thistory := &vault.Vault{Dir: filepath.Join(filepath.Dir(*accessFile), \"history\"), Key: gate.Key}\n" +
		"\t\tapi.KeepReports(history)\n" +
		"\t\troot.Handle(\"/api/v1/history\", history.Handler())\n" +
		"\t\troot.Handle(\"/api/v1/history/\", history.Handler())\n" +
		"\t}\n"
	if !strings.Contains(src, block) {
		t.Fatal("the vault is no longer made in the branch that makes the gate")
	}
	rest := strings.Replace(src, block, "", 1)
	for _, never := range []string{"KeepReports(", "history.Handler()", "vault.Vault{"} {
		if strings.Contains(rest, never) {
			t.Errorf("main.go uses %q outside the branch that makes the gate", never)
		}
	}
	if !strings.Contains(src, "if gate != nil {\n\t\thandler = gate.Wrap(root)\n\t}") {
		t.Error("the gate is not what the server is handed")
	}
}
