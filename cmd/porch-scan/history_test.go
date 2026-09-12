package main

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/results"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// A scan that failed is not kept as a verdict.
//
// The distinction R4 is written about, arriving on disk. A history holding a
// row for a target that was never reached reads as a server that was graded,
// and the next person comparing two dates would be comparing a measurement
// against a refusal.
//
// It is also what stops a crash. The command's result type embeds a pointer to
// the report, so reading a verdict off a scan that produced none dereferences
// nothing — the guard that keeps a failure out of the store is the same one
// that keeps the program running, and a sabotage removing it escaped every test
// here on 2026-09-12.
func TestAFailedScanIsNotKept(t *testing.T) {
	dir := t.TempDir()
	store := &results.Store{Dir: dir}

	// Refused before any lookup: the mail check takes a bare domain, and this
	// is not one. Nothing reaches the network.
	code := runMail(context.Background(), []string{"not a domain"}, time.Second, "", true, store, nil)
	if code == exitOK {
		t.Error("a target that cannot be scanned exited zero")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the store: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a failed scan wrote %d entries into the store", len(entries))
	}
}

// Nothing is written unless a directory was named.
func TestNothingIsKeptWithoutADirectory(t *testing.T) {
	dir := t.TempDir()

	// A store pointed nowhere, beside a directory that would show any writing.
	code := runMail(context.Background(), []string{"not a domain"}, time.Second, "",
		true, &results.Store{}, nil)
	if code == exitOK {
		t.Error("a target that cannot be scanned exited zero")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(entries) != 0 {
		t.Error("something was written when no directory was named")
	}
}

// -history reads what was kept and reaches nothing.
func TestHistoryReadsWhatWasKept(t *testing.T) {
	dir := t.TempDir()
	store := &results.Store{Dir: dir}

	for _, v := range []string{"strong", "weak"} {
		if err := store.Put("tls", "example.com_443", v, "porch-tls-v7", []string{"cert.expired"}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	var out strings.Builder
	// What an operator types, not the name it is filed under. printHistory
	// resolves the one into the other, which is the point of it.
	if code := printHistory(&out, store, checkTLS, []string{"example.com:443"}); code != exitOK {
		t.Fatalf("printHistory returned %d", code)
	}

	text := out.String()
	for _, want := range []string{"strong", "weak", "cert.expired", "porch-tls-v7"} {
		if !strings.Contains(text, want) {
			t.Errorf("the history does not carry %q:\n%s", want, text)
		}
	}
}

// A history that spans a rule-set change says where the line falls.
//
// The one thing that makes two rows incomparable, and the one a reader would
// not think to check. A server that went from strong to weak because a rule got
// stricter has not changed at all, and a table presenting the two rows side by
// side without saying so hands somebody a reason to go looking for a change
// that never happened.
func TestAHistorySaysWhereTheRulesChanged(t *testing.T) {
	dir := t.TempDir()
	store := &results.Store{Dir: dir}

	if err := store.Put("tls", "example.com_443", "strong", "porch-tls-v6", nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Put("tls", "example.com_443", "weak", "porch-tls-v7", nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var out strings.Builder
	printHistory(&out, store, checkTLS, []string{"example.com:443"})

	text := out.String()
	if !strings.Contains(text, "not comparable") {
		t.Errorf("a history spanning a rule-set change does not say so:\n%s", text)
	}
	if !strings.Contains(text, "porch-tls-v6 became porch-tls-v7") {
		t.Errorf("it does not say which change it was:\n%s", text)
	}
}

// A target never scanned and a store holding nothing read the same on disk, so
// the sentence says both rather than picking one (R4).
func TestAnEmptyHistorySaysWhatItDoesNotKnow(t *testing.T) {
	store := &results.Store{Dir: t.TempDir()}

	var out strings.Builder
	if code := printHistory(&out, store, "tls", []string{"never.example"}); code != exitOK {
		t.Fatalf("printHistory returned %d", code)
	}
	if !strings.Contains(out.String(), "has been kept here") {
		t.Errorf("an empty history claims something it cannot know:\n%s", out.String())
	}
}

// -history without -results-dir says why it has nothing, and fails.
func TestHistoryWithoutAStoreSaysSo(t *testing.T) {
	var out strings.Builder
	if code := printHistory(&out, &results.Store{}, "tls", []string{"example.com"}); code == exitOK {
		t.Error("asking for a history nothing was kept in exited zero")
	}
}

// Host and port stay apart in the name a history is filed under.
//
// Scanning one host on two ports is two different measurements — the service's
// own per-target budget says so — and folding them into one history would
// interleave two servers' verdicts under one name.
func TestAHistoryNameKeepsTheHostAndPortApart(t *testing.T) {
	for _, tc := range []struct{ check, target, want string }{
		{checkTLS, "example.com:443", "example.com_443"},
		{checkTLS, "example.com:8443", "example.com_8443"},

		// The default port is filled in, because a scan fills it in. This is
		// the case the first version got wrong: writing used the port a scan
		// resolved and reading used the bare name somebody typed.
		{checkTLS, "example.com", "example.com_443"},

		// The other two checks take a bare name. Giving them a default port
		// would file a history under a port nothing measured.
		{checkWeb, "example.com", "example.com"},
		{checkMail, "example.com", "example.com"},
	} {
		if got := historyName(tc.check, tc.target); got != tc.want {
			t.Errorf("historyName(%q, %q) = %q, want %q", tc.check, tc.target, got, tc.want)
		}
	}

	if historyName(checkTLS, "example.com:443") == historyName(checkTLS, "example.com:8443") {
		t.Error("two ports on one host share a history")
	}

	// And the name is one a store will accept, which is the whole reason the
	// colon is replaced rather than kept.
	store := &results.Store{Dir: t.TempDir()}
	if err := store.Put("tls", historyName(checkTLS, "example.com:443"), "strong", "porch-tls-v7", nil); err != nil {
		t.Errorf("the store refused a name this function produced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "tls", "example.com_443.jsonl")); err != nil {
		t.Errorf("the history was not filed where expected: %v", err)
	}
}

// What a scan writes is what -history reads.
//
// The two were written separately and disagreed: a TLS scan filed under
// host_port, because the scan fills in the default port, while -history looked
// for the bare name somebody typed. The web and mail checks take no port, so
// both worked and the defect was invisible until a TLS history was read back —
// found by running the thing rather than by any test here.
//
// So this asserts that the two agree rather than asserting two literals. Two
// literals is what the first version had, one on each side, and they were both
// correct about their own half.
func TestWhatAScanWritesIsWhatHistoryReads(t *testing.T) {
	for _, tc := range []struct{ check, typed, resolved string }{
		// What an operator types, and what the scan resolves it to. The TLS
		// check is the one where those differ.
		{checkTLS, "example.com", "example.com:443"},
		{checkTLS, "example.com:8443", "example.com:8443"},
		{checkWeb, "example.com", "example.com"},
		{checkMail, "example.com", "example.com"},
	} {
		store := &results.Store{Dir: t.TempDir()}

		// Written under the name the scan produces.
		written := historyName(tc.check, tc.resolved)
		if err := store.Put(tc.check, written, "strong", "porch-tls-v7", nil); err != nil {
			t.Fatalf("Put: %v", err)
		}

		// Read under the name somebody types.
		var out strings.Builder
		if code := printHistory(&out, store, tc.check, []string{tc.typed}); code != exitOK {
			t.Fatalf("printHistory returned %d", code)
		}

		if strings.Contains(out.String(), "has been kept here") {
			t.Errorf("a %s scan of %q was written as %q and -history %q found nothing:\n%s",
				tc.check, tc.resolved, written, tc.typed, out.String())
		}
	}
}

// A real TLS scan files its result where -history looks for it.
//
// The end-to-end version of the test above, and the one that would have caught
// the defect. The other asserts that two functions agree; this drives the code
// that calls them, because the escape was at the call site rather than in
// either function.
//
// Against a server started here, so nothing reaches the network.
func TestATLSScanFilesWhereHistoryLooks(t *testing.T) {
	port := testServer(t, serverOpts{
		names:      []string{"example.test"},
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(24 * time.Hour),
		minVersion: tls.VersionTLS12,
		maxVersion: tls.VersionTLS13,
	})

	scanner := &scan.Scanner{
		Prober:       &tlsprobe.Prober{Dial: toLoopback(port), TotalTimeout: 10 * time.Second},
		AllowAnyPort: true,
		Resolver:     noResolver(),
	}

	store := &results.Store{Dir: t.TempDir()}
	target := "example.test:" + port

	if code := runTLS(context.Background(), scanner, []string{target}, 10*time.Second, true, store); code == exitError {
		t.Fatalf("the scan failed, so this test proves nothing about where it files")
	}

	var out strings.Builder
	if code := printHistory(&out, store, checkTLS, []string{target}); code != exitOK {
		t.Fatalf("printHistory returned %d", code)
	}
	if strings.Contains(out.String(), "has been kept here") {
		t.Errorf("a scan of %q was kept somewhere -history does not look:\n%s\nstore holds: %v",
			target, out.String(), held(t, store))
	}
}

// held lists what is actually on disk, so a failure says where things went
// rather than only that they are not where they were expected.
func held(t *testing.T, store *results.Store) []string {
	t.Helper()

	var out []string
	_ = filepath.Walk(store.Dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			rel, _ := filepath.Rel(store.Dir, path)
			out = append(out, rel)
		}
		return nil
	})
	return out
}
