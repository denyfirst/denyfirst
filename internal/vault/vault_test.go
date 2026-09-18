package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func newVault(t *testing.T) (*Vault, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return &Vault{Dir: filepath.Join(t.TempDir(), "history"), Key: func() []byte { return key }}, key
}

const report = `{"target":"example.com","verdict":"strong","findings":[]}`

// A report kept comes back whole, and the list says what it is about.
func TestAKeptReportComesBackWhole(t *testing.T) {
	v, _ := newVault(t)
	if err := v.Keep("tls", "example.com", "strong", "porch-tls-v7", []byte(report)); err != nil {
		t.Fatal(err)
	}
	entries, err := v.List()
	if err != nil || len(entries) != 1 {
		t.Fatalf("the list holds %d reports: %v", len(entries), err)
	}
	e := entries[0]
	if e.Check != "tls" || e.Target != "example.com" || e.Verdict != "strong" || e.Policy != "porch-tls-v7" {
		t.Errorf("the list misdescribes the report: %+v", e)
	}
	rec, err := v.Get(e.ID)
	if err != nil || string(rec.Report) != report {
		t.Errorf("the report did not come back whole: %v %s", err, rec.Report)
	}
}

// On disk there is nothing readable: not the target, not the verdict, and
// not the target in a file's name.
func TestNothingOnDiskIsReadable(t *testing.T) {
	v, key := newVault(t)
	if err := v.Keep("tls", "secret-estate.example", "insecure", "porch-tls-v7", []byte(`{"target":"secret-estate.example"}`)); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(v.Dir)
	if len(files) != 1 {
		t.Fatalf("%d files for one report", len(files))
	}
	name := files[0].Name()
	if strings.Contains(name, "secret") || strings.Contains(name, "example") {
		t.Errorf("a file is named after its target: %s", name)
	}
	body, _ := os.ReadFile(filepath.Join(v.Dir, name))
	for _, plain := range [][]byte{[]byte("secret-estate"), []byte("insecure"), []byte("porch-tls"), key} {
		if bytes.Contains(body, plain) {
			t.Errorf("the sealed report carries %q in the clear", plain)
		}
	}
	if os.PathSeparator == '/' {
		if info, _ := os.Stat(v.Dir); info.Mode().Perm()&0o077 != 0 {
			t.Errorf("the history directory is open to others: %v", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Join(v.Dir, name)); info.Mode().Perm()&0o077 != 0 {
			t.Errorf("a report is readable by others: %v", info.Mode().Perm())
		}
	}
}

// Without the key nothing is kept and nothing is read, and a report under
// another key does not open.
func TestWithoutTheKeyNothingIsKeptOrRead(t *testing.T) {
	locked := &Vault{Dir: filepath.Join(t.TempDir(), "history"), Key: func() []byte { return nil }}
	if err := locked.Keep("tls", "example.com", "strong", "p", []byte(report)); !errors.Is(err, ErrLocked) {
		t.Errorf("a vault with no key kept a report: %v", err)
	}
	if _, err := os.Stat(locked.Dir); !os.IsNotExist(err) {
		t.Error("a vault with no key wrote to disk")
	}

	v, _ := newVault(t)
	_ = v.Keep("tls", "example.com", "strong", "p", []byte(report))
	entries, _ := v.List()

	other := make([]byte, 32)
	other[0] = 1
	stranger := &Vault{Dir: v.Dir, Key: func() []byte { return other }}
	if list, _ := stranger.List(); len(list) != 0 {
		t.Error("another key lists the reports")
	}
	if _, err := stranger.Get(entries[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another key opened a report: %v", err)
	}
}

// A sealed report moved to another report's name does not open: the name is
// authenticated with it.
func TestAReportMovedToAnotherNameDoesNotOpen(t *testing.T) {
	v, _ := newVault(t)
	_ = v.Keep("tls", "a.example", "strong", "p", []byte(`{"n":1}`))
	_ = v.Keep("tls", "b.example", "weak", "p", []byte(`{"n":2}`))
	entries, _ := v.List()
	a, b := v.path(entries[0].ID), v.path(entries[1].ID)
	body, _ := os.ReadFile(a)
	if err := os.WriteFile(b, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(entries[1].ID); err == nil {
		t.Error("a report copied over another's name opened as that report")
	}
}

// Delete removes the file for good, and an identifier cannot name a path.
func TestDeleteRemovesTheReportAndOnlyIt(t *testing.T) {
	v, _ := newVault(t)
	_ = v.Keep("tls", "a.example", "strong", "p", []byte(`{"n":1}`))
	_ = v.Keep("web", "a.example", "weak", "p", []byte(`{"n":2}`))
	entries, _ := v.List()

	if err := v.Delete(entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.path(entries[0].ID)); !os.IsNotExist(err) {
		t.Error("a deleted report's file is still there")
	}
	left, _ := v.List()
	if len(left) != 1 || left[0].ID != entries[1].ID {
		t.Errorf("deleting one report touched another: %+v", left)
	}
	for _, id := range []string{"../access", "..%2faccess", strings.Repeat("A", 32), strings.Repeat("0", 31), ""} {
		if err := v.Delete(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(%q): %v, want ErrNotFound", id, err)
		}
	}
}

// Newest first, by date then by the order kept; past the bound the oldest go.
func TestTheHistoryIsNewestFirstAndBounded(t *testing.T) {
	v, _ := newVault(t)
	v.Limit = 3
	day := "2026-09-01"
	v.Today = func() string { return day }
	for i, d := range []string{"2026-09-01", "2026-09-01", "2026-09-02", "2026-09-03"} {
		day = d
		if err := v.Keep("tls", "n"+string(rune('a'+i))+".example", "strong", "p", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := v.List()
	var got []string
	for _, e := range entries {
		got = append(got, e.Target)
	}
	if strings.Join(got, " ") != "nd.example nc.example nb.example" {
		t.Errorf("the history reads %v, want the three newest, newest first", got)
	}
	for _, e := range entries {
		if len(e.Date) != len("2026-09-01") {
			t.Errorf("a report carries %q, which is more than a date", e.Date)
		}
	}
}

// Over HTTP: the list, one report, and deletion from this installation's own
// pages only.
func TestTheHandlerListsOpensAndDeletes(t *testing.T) {
	v, _ := newVault(t)
	_ = v.Keep("tls", "example.com", "strong", "p", []byte(report))
	entries, _ := v.List()
	h := v.Handler()

	do := func(method, path string, header map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		for k, val := range header {
			r.Header.Set(k, val)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := do(http.MethodGet, "/api/v1/history", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), entries[0].ID) {
		t.Errorf("the list: %d %s", w.Code, w.Body.String())
	}
	w := do(http.MethodGet, "/api/v1/history/"+entries[0].ID, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"verdict":"strong"`) {
		t.Errorf("one report: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("a report is answered cacheable")
	}
	if w := do(http.MethodDelete, "/api/v1/history/"+entries[0].ID, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site deletion: %d", w.Code)
	}
	if w := do(http.MethodDelete, "/api/v1/history/"+entries[0].ID, map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != http.StatusNoContent {
		t.Errorf("a deletion from this page: %d", w.Code)
	}
	if w := do(http.MethodGet, "/api/v1/history/"+entries[0].ID, nil); w.Code != http.StatusNotFound {
		t.Errorf("a deleted report: %d", w.Code)
	}
	if w := do(http.MethodPost, "/api/v1/history", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the list: %d", w.Code)
	}
}

// The name is bound by the seal itself, not only by the identifier inside:
// a report sealed for one name and moved to another does not open, even when
// what it says inside names the new one.
func TestTheSealBindsTheName(t *testing.T) {
	v, _ := newVault(t)
	gcm, err := v.cipher()
	if err != nil {
		t.Fatal(err)
	}
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if err := os.MkdirAll(v.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"` + b + `","check":"tls","target":"x.example","date":"2026-09-01","report":{}}`)
	if err := v.write(gcm, a, body); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(v.path(a), v.path(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(b); err == nil {
		t.Error("a report sealed under one name opened under another")
	}
}

// Only the names this package makes are names: thirty-two lowercase hex.
func TestOnlyThisPackagesNamesAreNames(t *testing.T) {
	for _, id := range []string{strings.Repeat("0", 30), strings.Repeat("0", 34), strings.Repeat("A", 32), "../" + strings.Repeat("0", 29), ""} {
		if validID(id) {
			t.Errorf("%q is accepted as a report name", id)
		}
	}
	if !validID(strings.Repeat("0f", 16)) {
		t.Error("a name this package makes is refused")
	}
}

// Two reports about the same name share nothing in their file names, and a
// report is dated, not timed, whatever the clock says.
func TestAFileNameSaysNothingAndADateIsOnlyADate(t *testing.T) {
	v, _ := newVault(t)
	for range 2 {
		if err := v.Keep("tls", "same.example", "strong", "p", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := os.ReadDir(v.Dir)
	if len(files) != 2 {
		t.Fatalf("%d files for two reports", len(files))
	}
	x, y := files[0].Name(), files[1].Name()
	for i := 0; i+4 <= 32; i += 4 {
		if x[i:i+4] == y[i:i+4] && i >= 24 {
			t.Errorf("two reports about one name share %q at the same place in their names", x[i:i+4])
		}
	}
	entries, _ := v.List()
	for _, e := range entries {
		if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(e.Date) {
			t.Errorf("a report is kept with %q, which is more than a date", e.Date)
		}
	}
}
