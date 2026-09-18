package vault

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Domains is the list of domains somebody behind the password has added, kept
// in one file sealed under the same key as the history.
//
// Only the names and the date each was added. Whether a domain is proven is
// not kept: it is a fact about its DNS today, asked again each time the list
// is shown, so a record deleted from the zone reads as unproven at once
// rather than as the "proven" somebody saw last week.
type Domains struct {
	// Path is the sealed file. Created, readable by this user alone, when the
	// first domain is added.
	Path string

	// Key returns the data key, or nil before anybody has signed in.
	Key func() []byte

	// Today is the date a domain is added under. Nil means today, in UTC.
	Today func() string

	mu sync.Mutex
}

// Domain is one added name.
type Domain struct {
	Name  string `json:"name"`
	Added string `json:"added"`
}

// MaxDomains bounds the list. Nobody proves this many; the bound is on what a
// request may grow.
const MaxDomains = 500

// domainBound is what Add enforces: MaxDomains, except in this package's
// tests, which lower it rather than write five hundred sealed lists.
var domainBound = MaxDomains

const domainsSeal = "porch-domains-v1"

// ErrNotADomain is a name the list will not hold.
var ErrNotADomain = errors.New("a domain is a name such as example.com: letters, digits and hyphens, in two labels or more")

// ErrFull is a list at MaxDomains.
var ErrFull = fmt.Errorf("the list holds at most %d domains", MaxDomains)

// List returns the added domains, by name.
func (d *Domains) List() ([]Domain, error) {
	gcm, err := sealer(d.Key)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.read(gcm)
}

// Add puts a domain on the list. Adding one that is there already changes
// nothing, and says so by returning false.
func (d *Domains) Add(name string) (bool, error) {
	name, ok := Normalise(name)
	if !ok {
		return false, ErrNotADomain
	}
	gcm, err := sealer(d.Key)
	if err != nil {
		return false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	list, err := d.read(gcm)
	if err != nil {
		return false, err
	}
	for _, x := range list {
		if x.Name == name {
			return false, nil
		}
	}
	if len(list) >= domainBound {
		return false, ErrFull
	}
	today := time.Now().UTC().Format("2006-01-02")
	if d.Today != nil {
		today = d.Today()
	}
	list = append(list, Domain{Name: name, Added: today})
	return true, d.write(gcm, list)
}

// Remove takes a domain off the list. What was kept about it in the history
// stays; that is deleted report by report.
func (d *Domains) Remove(name string) error {
	name, ok := Normalise(name)
	if !ok {
		return ErrNotFound
	}
	gcm, err := sealer(d.Key)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	list, err := d.read(gcm)
	if err != nil {
		return err
	}
	kept := list[:0]
	for _, x := range list {
		if x.Name != name {
			kept = append(kept, x)
		}
	}
	if len(kept) == len(list) {
		return ErrNotFound
	}
	return d.write(gcm, kept)
}

func (d *Domains) read(gcm cipher.AEAD) ([]Domain, error) {
	body, err := os.ReadFile(d.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("the domain list could not be read: %w", err)
	}
	if len(body) < gcm.NonceSize() {
		return nil, errors.New("the domain list is not one this key opens")
	}
	plain, err := gcm.Open(nil, body[:gcm.NonceSize()], body[gcm.NonceSize():], []byte(domainsSeal))
	if err != nil {
		return nil, errors.New("the domain list is not one this key opens")
	}
	var list []Domain
	if err := json.Unmarshal(plain, &list); err != nil {
		return nil, errors.New("the domain list is not one this key opens")
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (d *Domains) write(gcm cipher.AEAD, list []Domain) error {
	body, err := json.Marshal(list)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("a nonce could not be generated: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, body, []byte(domainsSeal))

	dir := filepath.Dir(d.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("the domain list could not be kept: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".domains-*")
	if err != nil {
		return fmt.Errorf("the domain list could not be kept: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the domain list could not be kept: %w", err)
	}
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the domain list could not be kept: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("the domain list could not be kept: %w", err)
	}
	if err := os.Rename(name, d.Path); err != nil {
		return fmt.Errorf("the domain list could not be kept: %w", err)
	}
	return nil
}

// Normalise returns a domain as the list holds it, lowercased and without a
// trailing dot, and whether it is one: two labels or more, each of letters,
// digits and hyphens, not starting or ending with a hyphen.
func Normalise(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return name, true
}

// Handler serves the list to somebody already signed in, behind the gate.
//
//	GET    /api/v1/domains          the list, by name
//	POST   /api/v1/domains          {"domain": "example.com"} added
//	DELETE /api/v1/domains/{name}   taken off the list
func (d *Domains) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/domains")
		if !ok {
			refuse(w, http.StatusNotFound, "not_found", "There is nothing here.")
			return
		}
		name, one := strings.CutPrefix(rest, "/")
		switch {
		case rest == "" && r.Method == http.MethodGet:
			list, err := d.List()
			if err != nil {
				failed(w, err)
				return
			}
			if list == nil {
				list = []Domain{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"domains": list})
		case rest == "" && r.Method == http.MethodPost:
			if !fromThisPage(r) {
				refuse(w, http.StatusForbidden, "cross_site", "Add domains from this installation's own pages.")
				return
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				refuse(w, http.StatusUnsupportedMediaType, "unsupported_media", "Send application/json.")
				return
			}
			var body struct {
				Domain string `json:"domain"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&body); err != nil {
				refuse(w, http.StatusBadRequest, "invalid_body", "Send a domain.")
				return
			}
			added, err := d.Add(body.Domain)
			switch {
			case errors.Is(err, ErrNotADomain):
				// The rule, not the input (I6).
				refuse(w, http.StatusBadRequest, "invalid_domain",
					"A domain is a name such as example.com: letters, digits and hyphens, in two labels or more.")
				return
			case errors.Is(err, ErrFull):
				refuse(w, http.StatusBadRequest, "full", fmt.Sprintf("The list holds at most %d domains.", MaxDomains))
				return
			case err != nil:
				failed(w, err)
				return
			}
			status := http.StatusCreated
			if !added {
				status = http.StatusOK
			}
			w.WriteHeader(status)
		case one && r.Method == http.MethodDelete:
			if !fromThisPage(r) {
				refuse(w, http.StatusForbidden, "cross_site", "Remove domains from this installation's own pages.")
				return
			}
			if err := d.Remove(name); err != nil {
				failed(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			refuse(w, http.StatusMethodNotAllowed, "method", "Read the list with GET, add with POST, and remove with DELETE.")
		}
	})
}
