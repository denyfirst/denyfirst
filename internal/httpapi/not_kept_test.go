package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/results"
)

// A result that could not be kept is said without saying which.
//
// The history file is named after the target, so a file-system error carries
// the target in its path. Before the 2026-09-16 audit (A23) that error was
// logged whole, with a timestamp: a line saying who was scanned, and when, in
// the one place the service writes that nobody set out to keep.
func TestAResultNotKeptIsSaidWithoutTheTarget(t *testing.T) {
	var said bytes.Buffer
	previous := notKeptLog
	notKeptLog = &said
	t.Cleanup(func() { notKeptLog = previous })

	// A file where the directory should be, so nothing can be written under
	// it and the error names a path beneath it.
	dir := filepath.Join(t.TempDir(), "private-results-dir")
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	s := webServer(t, offlineWebScanner())
	s.KeepResults(&results.Store{Dir: dir})

	w := postWeb(t, s, `{"target":"secret-internal-name.test"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	line := said.String()
	if !strings.HasPrefix(line, "a result was not kept: ") || strings.Count(line, "\n") != 1 {
		t.Fatalf("the failure was not said as one line: %q", line)
	}
	for _, leak := range []string{"secret-internal-name", "private-results-dir", "2026", ":"} {
		rest := strings.TrimPrefix(line, "a result was not kept: ")
		if leak == ":" {
			// The operation and the reason are joined by one colon, and a
			// timestamp would bring more.
			if strings.Count(rest, ":") > 1 {
				t.Errorf("the line carries more than an operation and a reason: %q", line)
			}
			continue
		}
		if strings.Contains(line, leak) {
			t.Errorf("the line carries %q: %q", leak, line)
		}
	}
	if strings.Contains(w.Body.String(), "not kept") {
		t.Error("the caller was told about the operator's store")
	}
}

// What is kept of an error is its operation and the system's reason, and
// nothing that is not a file-system error is repeated at all.
func TestNotKeptKeepsOnlyTheReason(t *testing.T) {
	path := &os.PathError{Op: "open", Path: "/srv/results/tls/secret.test.jsonl", Err: os.ErrPermission}
	if got := notKept(path); got != "a result was not kept: open: permission denied" {
		t.Errorf("a path error became %q", got)
	}
	link := &os.LinkError{Op: "rename", Old: "/srv/a/secret.test", New: "/srv/b/secret.test", Err: os.ErrExist}
	if got := notKept(link); strings.Contains(got, "secret") || !strings.Contains(got, "rename") {
		t.Errorf("a link error became %q", got)
	}
	other := errors.New("results: the target is not a bare name: secret.test/..")
	if got := notKept(other); strings.Contains(got, "secret") {
		t.Errorf("another error became %q", got)
	}
}

// The EHLO name an operator gives reaches the exchangers.
func TestTheEHLONameReachesTheMailCheck(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)
	if s.mail.HeloName != "" {
		t.Fatalf("a server nobody configured gives %q", s.mail.HeloName)
	}
	s.UseHeloName("scanner.example.test")
	if s.mail.HeloName != "scanner.example.test" {
		t.Errorf("the mail check gives %q", s.mail.HeloName)
	}
}
