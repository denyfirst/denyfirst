package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/results"
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
	code := runMail(context.Background(), []string{"not a domain"}, time.Second, "", true, store)
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
		true, &results.Store{})
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
	if code := printHistory(&out, store, "tls", []string{"example.com_443"}); code != exitOK {
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
	printHistory(&out, store, "tls", []string{"example.com_443"})

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
	for _, tc := range []struct{ target, want string }{
		{"example.com:443", "example.com_443"},
		{"example.com:8443", "example.com_8443"},
		{"example.com", "example.com"},
	} {
		if got := historyName(tc.target); got != tc.want {
			t.Errorf("historyName(%q) = %q, want %q", tc.target, got, tc.want)
		}
	}

	if historyName("example.com:443") == historyName("example.com:8443") {
		t.Error("two ports on one host share a history")
	}

	// And the name is one a store will accept, which is the whole reason the
	// colon is replaced rather than kept.
	store := &results.Store{Dir: t.TempDir()}
	if err := store.Put("tls", historyName("example.com:443"), "strong", "porch-tls-v7", nil); err != nil {
		t.Errorf("the store refused a name this function produced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "tls", "example.com_443.jsonl")); err != nil {
		t.Errorf("the history was not filed where expected: %v", err)
	}
}
