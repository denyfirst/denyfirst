package results

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func store(t *testing.T, keep int) *Store {
	t.Helper()

	day := 0
	return &Store{
		Dir:  t.TempDir(),
		Keep: keep,
		Now: func() time.Time {
			day++
			return time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC)
		},
	}
}

// Nothing is kept unless somebody said where to keep it.
//
// The default this whole package exists under. A caller that was never told a
// directory gets a store that writes nothing and reads nothing, and a nil one
// does the same so no caller has to branch.
func TestAStoreWithNoDirectoryKeepsNothing(t *testing.T) {
	for _, s := range []*Store{nil, {}, {Dir: ""}} {
		if s.Enabled() {
			t.Errorf("%+v reports itself as keeping records", s)
		}
		if err := s.Put("tls", "example.com", "strong", "porch-tls-v7", nil); err != nil {
			t.Errorf("Put on a store that keeps nothing: %v", err)
		}
		got, err := s.History("tls", "example.com")
		if err != nil {
			t.Errorf("History on a store that keeps nothing: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("a store that keeps nothing returned %+v", got)
		}
	}
}

// What goes in comes back, oldest first.
func TestWhatIsKeptComesBackInOrder(t *testing.T) {
	s := store(t, 0)

	for _, v := range []string{"strong", "weak", "insecure"} {
		if err := s.Put("tls", "example.com", v, "porch-tls-v7", []string{"cert.expired"}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	got, err := s.History("tls", "example.com")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3: %+v", len(got), got)
	}
	for i, want := range []string{"strong", "weak", "insecure"} {
		if got[i].Verdict != want {
			t.Errorf("record %d is %q, want %q", i, got[i].Verdict, want)
		}
	}

	// The rule set travels with the verdict. A history spanning a rule-set
	// change holds verdicts that are not comparable, and this is the only
	// thing that says where the line falls.
	for _, r := range got {
		if r.Policy != "porch-tls-v7" {
			t.Errorf("a record carries policy %q", r.Policy)
		}
		if r.Check != "tls" {
			t.Errorf("a record carries check %q", r.Check)
		}
		if r.Date == "" {
			t.Error("a record carries no date, so nothing can be compared against anything")
		}
	}
}

// One check's history is not another's.
func TestTheThreeChecksAreKeptApart(t *testing.T) {
	s := store(t, 0)

	if err := s.Put("tls", "example.com", "strong", "porch-tls-v7", nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put("mail", "example.com", "weak", "porch-mail-v1", nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	tls, err := s.History("tls", "example.com")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(tls) != 1 || tls[0].Verdict != "strong" {
		t.Errorf("the TLS history is %+v", tls)
	}

	mail, err := s.History("mail", "example.com")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(mail) != 1 || mail[0].Verdict != "weak" {
		t.Errorf("the mail history is %+v", mail)
	}
}

// Keep bounds a target's history, and the newest survive.
//
// Unset keeps everything, because a number this project chose would be a
// threshold nobody can argue with (R21) applied to somebody's disk.
func TestKeepBoundsAHistoryAndDropsTheOldest(t *testing.T) {
	s := store(t, 2)

	for _, v := range []string{"strong", "weak", "insecure"} {
		if err := s.Put("tls", "example.com", v, "porch-tls-v7", nil); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	got, err := s.History("tls", "example.com")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(got), got)
	}
	if got[0].Verdict != "weak" || got[1].Verdict != "insecure" {
		t.Errorf("the wrong records survived: %+v", got)
	}
}

// A target cannot write outside the directory it was given.
//
// The name goes into a path, which is what makes a store something an operator
// can look through with the tools they already have — and is only safe because
// the name is checked first. Checked rather than escaped, for the reason this
// project checks hostnames everywhere: an allow list cannot be surprised by
// something nobody thought to forbid.
func TestATargetCannotEscapeTheDirectory(t *testing.T) {
	s := store(t, 0)

	bad := []string{
		"../outside",
		"..",
		".",
		"a/b",
		"/etc/passwd",
		"example.com/../../x",
		"",
		"exam ple.com",
		strings.Repeat("a", 300),
	}
	bad = append(bad, "a"+string(os.PathSeparator)+"b")
	bad = append(bad, "exam\nple.com")

	for _, target := range bad {
		if err := s.Put("tls", target, "strong", "porch-tls-v7", nil); err == nil {
			t.Errorf("Put accepted the target %q", target)
		}
		if _, err := s.History("tls", target); err == nil {
			t.Errorf("History accepted the target %q", target)
		}
	}

	// And the check name is checked for the same reason: it is the other half
	// of the path.
	if err := s.Put("../tls", "example.com", "strong", "porch-tls-v7", nil); err == nil {
		t.Error("Put accepted a check name that climbs out of the directory")
	}

	// Nothing was created outside.
	entries, err := os.ReadDir(filepath.Dir(s.Dir))
	if err != nil {
		t.Fatalf("reading the parent: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "outside") {
			t.Errorf("a file was written outside the store: %s", e.Name())
		}
	}
}

// The store is readable only by the person who runs it.
//
// A history of an estate's weaknesses is the most useful thing on the machine
// to somebody who should not have it. Windows does not enforce the mode bits
// this way, so the assertion runs where it means something.
func TestTheStoreIsKeptToItsOwner(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("file modes are not enforced this way here; the program still asks for 0600")
	}

	s := store(t, 0)
	if err := s.Put("tls", "example.com", "strong", "porch-tls-v7", nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	info, err := os.Stat(filepath.Join(s.Dir, "tls", "example.com.jsonl"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the store is readable beyond its owner: %v", mode)
	}
}

// A half-written line loses that line and nothing else.
//
// The failure most likely to actually happen — a full disk, a machine that went
// away mid-write — and refusing the whole history because of it would lose
// everything to the one thing this store should survive.
func TestACorruptLineLosesOnlyItself(t *testing.T) {
	s := store(t, 0)

	if err := s.Put("tls", "example.com", "strong", "porch-tls-v7", nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	path := filepath.Join(s.Dir, "tls", "example.com.jsonl")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	halfWritten := body
	halfWritten = append(halfWritten, []byte(`{"date":"2026-09-`)...)
	halfWritten = append(halfWritten, '\n')
	if err := os.WriteFile(path, halfWritten, fileMode); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if err := s.Put("tls", "example.com", "weak", "porch-tls-v7", nil); err != nil {
		t.Fatalf("Put after a half-written line: %v", err)
	}

	got, err := s.History("tls", "example.com")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want the two good ones: %+v", len(got), got)
	}
	if got[0].Verdict != "strong" || got[1].Verdict != "weak" {
		t.Errorf("the surviving records are %+v", got)
	}
}

// What is stored is what a report already carries, and nothing more.
//
// Writing a report down does not relax what a report may contain. The fields
// here are ones a report already has; a store that grew a client address or a
// time of day would be recording something no report holds, in a file nobody
// expected to hold it.
func TestNothingIsStoredThatAReportDoesNotAlreadyCarry(t *testing.T) {
	s := store(t, 0)
	if err := s.Put("tls", "example.com", "strong", "porch-tls-v7", []string{"cert.expired"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(s.Dir, "tls", "example.com.jsonl"))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	// The date, and nothing finer. The project's retention language is
	// "nothing beyond a date", and this is the one place a scanner would
	// casually write a timestamp without thinking about it.
	text := string(body)
	if !strings.Contains(text, `"date":"2026-09-01"`) {
		t.Errorf("the record carries no plain date: %s", text)
	}
	for _, forbidden := range []string{"T12:", "12:00:00"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the record carries a time of day (%q): %s", forbidden, text)
		}
	}
}

// A store with no directory cannot write into the working directory.
//
// Enabled is the guard, and this is the second one behind it.
// filepath.Join("", "tls", x) is a relative path, so a store that got past
// Enabled with no directory would write into whatever the program was started
// from — for a service, wherever systemd left it; for a container, "/". A
// sabotage broke Enabled on 2026-09-12 and the store wrote a file into the
// source tree within seconds, which is the harmless version of exactly that.
func TestAStoreWithNoDirectoryCannotWriteRelative(t *testing.T) {
	// Reaching past Enabled deliberately, which is what a defect in it would do.
	s := &Store{}

	if _, err := s.pathFor("tls", "example.com"); err == nil {
		t.Error("a store with no directory produced a path, which would be relative to wherever " +
			"the program was started")
	}

	// And nothing lands beside this test when the guard above it is the only
	// thing that ran.
	dir := t.TempDir()
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Store{}).Put("tls", "example.com", "strong", "porch-tls-v7", nil); err != nil {
		t.Errorf("Put on a disabled store: %v", err)
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Error("something was written by a store that keeps nothing")
	}
}
