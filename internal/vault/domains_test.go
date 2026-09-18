package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newDomains(t *testing.T) (*Domains, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return &Domains{Path: filepath.Join(t.TempDir(), "domains.sealed"), Key: func() []byte { return key }}, key
}

// Domains are added once, listed by name, removed one at a time, and kept
// with the date they were added and nothing else: not whether they were
// proven, which is asked again each time.
func TestTheDomainListAddsListsAndRemoves(t *testing.T) {
	d, _ := newDomains(t)
	d.Today = func() string { return "2026-09-18" }

	for _, name := range []string{"b.example", "A.Example.", "a.example"} {
		if _, err := d.Add(name); err != nil {
			t.Fatalf("adding %q: %v", name, err)
		}
	}
	list, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "a.example" || list[1].Name != "b.example" {
		t.Fatalf("the list is %+v, want a.example and b.example once each, by name", list)
	}
	if list[0].Added != "2026-09-18" {
		t.Errorf("a domain was added under %q", list[0].Added)
	}
	if added, _ := d.Add("a.example"); added {
		t.Error("adding a domain already there said it was added")
	}
	if err := d.Remove("A.EXAMPLE"); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.List(); len(list) != 1 || list[0].Name != "b.example" {
		t.Errorf("removing one domain left %+v", list)
	}
	if err := d.Remove("not.there"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing a domain not there: %v", err)
	}
}

// Only a domain is a domain.
func TestOnlyADomainIsAdded(t *testing.T) {
	d, _ := newDomains(t)
	for _, bad := range []string{"", "localhost", "https://example.com", "example.com/path", "exa mple.com", "-a.example", "a-.example", "a..example", "example.com:443", "user@example.com", strings.Repeat("a", 64) + ".example"} {
		if _, err := d.Add(bad); !errors.Is(err, ErrNotADomain) {
			t.Errorf("%q: %v, want ErrNotADomain", bad, err)
		}
	}
	if _, err := os.Stat(d.Path); !os.IsNotExist(err) {
		t.Error("a refused name was written")
	}
}

// Nothing on disk is readable, and without the key nothing is added or read.
func TestTheDomainListIsSealed(t *testing.T) {
	d, key := newDomains(t)
	if _, err := d.Add("secret-estate.example"); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(d.Path)
	if bytes.Contains(body, []byte("secret-estate")) || bytes.Contains(body, key) {
		t.Error("the domain list carries a name or the key in the clear")
	}
	if os.PathSeparator == '/' {
		if info, _ := os.Stat(d.Path); info.Mode().Perm()&0o077 != 0 {
			t.Errorf("the domain list is readable by others: %v", info.Mode().Perm())
		}
	}

	locked := &Domains{Path: filepath.Join(t.TempDir(), "d"), Key: func() []byte { return nil }}
	if _, err := locked.Add("a.example"); !errors.Is(err, ErrLocked) {
		t.Errorf("a list with no key added a domain: %v", err)
	}
	other := make([]byte, 32)
	stranger := &Domains{Path: d.Path, Key: func() []byte { return other }}
	if _, err := stranger.List(); err == nil {
		t.Error("another key opened the domain list")
	}
}

// The list is bounded.
func TestTheDomainListIsBounded(t *testing.T) {
	if !strings.Contains(readFile(t, "domains.go"), "var domainBound = MaxDomains\n") {
		t.Error("the bound the program enforces is not MaxDomains")
	}
	saved := domainBound
	domainBound = 5
	t.Cleanup(func() { domainBound = saved })

	d, _ := newDomains(t)
	for i := range domainBound {
		if _, err := d.Add("d" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + "-" + itoa(i) + ".example"); err != nil {
			t.Fatalf("adding domain %d: %v", i, err)
		}
	}
	if _, err := d.Add("one-more.example"); !errors.Is(err, ErrFull) {
		t.Errorf("a full list took another: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// Over HTTP: listed, added as JSON from this installation's own pages, and
// removed; a refusal names the rule, not the input.
func TestTheDomainHandler(t *testing.T) {
	d, _ := newDomains(t)
	h := d.Handler()
	do := func(method, path, body string, header map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := do(http.MethodPost, "/api/v1/domains", `{"domain":"example.com"}`, nil); w.Code != http.StatusCreated {
		t.Fatalf("adding: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/api/v1/domains", `{"domain":"example.com"}`, nil); w.Code != http.StatusOK {
		t.Errorf("adding again: %d", w.Code)
	}
	w := do(http.MethodPost, "/api/v1/domains", `{"domain":"<script>evil"}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "evil") {
		t.Errorf("a bad name: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodPost, "/api/v1/domains", `{"domain":"a.example"}`, map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site add: %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/domains", strings.NewReader("domain=a.example"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a form post: %d", rec.Code)
	}
	if w := do(http.MethodGet, "/api/v1/domains", "", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"example.com"`) {
		t.Errorf("the list: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/api/v1/domains/example.com", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site removal: %d", w.Code)
	}
	if w := do(http.MethodDelete, "/api/v1/domains/example.com", "", nil); w.Code != http.StatusNoContent {
		t.Errorf("removing: %d", w.Code)
	}
	if w := do(http.MethodGet, "/api/v1/domains", "", nil); strings.Contains(w.Body.String(), "example.com") {
		t.Errorf("a removed domain is still listed: %s", w.Body.String())
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
