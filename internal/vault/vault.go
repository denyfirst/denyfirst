// Package vault keeps the reports an installation behind a password has
// produced, encrypted under the key the password seals.
//
// Every check's report is kept, whole, so it can be opened again exactly as
// it was drawn, and each can be deleted for good. Nothing is kept until
// somebody has signed in since the program started, because until then there
// is no key: a vault without one refuses to write rather than writing in the
// clear.
//
// On disk each report is one file:
//
//   - named by a random identifier, so a directory listing says how many
//     reports there are and nothing about which names they are about;
//   - holding a nonce and the report sealed with AES-256-GCM under the data
//     key, with the file's own name authenticated beside it, so a sealed
//     report moved to another name does not open;
//   - carrying a date, not a time, as everything else this project keeps.
//
// Deleting a report removes its file. The bytes may outlive that on the disk
// underneath, as removed files do; what outlives it is ciphertext under a key
// that exists only in the running process and sealed by the password.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultKeep is how many reports are kept when Limit is zero. The oldest go
// first.
const DefaultKeep = 1000

// maxReport bounds what is sealed. A report is tens of kilobytes; this is a
// bound, not a size anybody reaches.
const maxReport = 4 << 20

const (
	suffix   = ".sealed"
	sealBase = "porch-history-v1:"
)

// ErrLocked is what a vault with no key answers: nothing is kept until
// somebody has signed in since the program started.
var ErrLocked = errors.New("nothing can be kept or read until somebody signs in")

// ErrNotFound is a report that is not there, or not one this key opens.
var ErrNotFound = errors.New("there is no such report")

// Entry is what the list shows of one report.
type Entry struct {
	ID      string `json:"id"`
	Check   string `json:"check"`
	Target  string `json:"target"`
	Date    string `json:"date"`
	Verdict string `json:"verdict"`
	Policy  string `json:"policy"`

	// Seq orders reports kept on the same date. A counter, not a time.
	Seq int64 `json:"seq"`
}

// Record is a report as it was kept.
type Record struct {
	Entry
	Report json.RawMessage `json:"report"`
}

// Vault is a directory of sealed reports.
type Vault struct {
	// Dir is where the reports are. Created, readable by this user alone, on
	// the first report kept.
	Dir string

	// Key returns the data key, or nil before anybody has signed in.
	Key func() []byte

	// Limit bounds how many reports are kept. Zero means DefaultKeep.
	Limit int

	// Today is the date a report is kept under. Nil means today, in UTC.
	Today func() string

	mu sync.Mutex
}

// Keep seals one report and writes it, dropping the oldest past the bound.
// The signature is internal/httpapi's Keeper.
func (v *Vault) Keep(check, target, verdict, policy string, report []byte) error {
	if len(report) > maxReport || !json.Valid(report) {
		return errors.New("the report is not one this vault keeps")
	}
	gcm, err := v.cipher()
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	entries, err := v.entries(gcm)
	if err != nil {
		return err
	}
	var seq int64
	for _, e := range entries {
		seq = max(seq, e.Seq)
	}

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("a report name could not be generated: %w", err)
	}
	id := hex.EncodeToString(raw)
	body, err := json.Marshal(Record{
		Entry: Entry{
			ID:      id,
			Check:   check,
			Target:  target,
			Date:    v.today(),
			Verdict: verdict,
			Policy:  policy,
			Seq:     seq + 1,
		},
		Report: report,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(v.Dir, 0o700); err != nil {
		return fmt.Errorf("the history directory could not be made: %w", err)
	}
	if err := v.write(gcm, id, body); err != nil {
		return err
	}

	// Past the bound, the oldest go.
	keep := v.Limit
	if keep <= 0 {
		keep = DefaultKeep
	}
	if extra := len(entries) + 1 - keep; extra > 0 {
		sortNewestFirst(entries)
		for _, e := range entries[len(entries)-extra:] {
			_ = os.Remove(v.path(e.ID))
		}
	}
	return nil
}

// List returns what is kept, newest first.
func (v *Vault) List() ([]Entry, error) {
	gcm, err := v.cipher()
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	entries, err := v.entries(gcm)
	if err != nil {
		return nil, err
	}
	sortNewestFirst(entries)
	return entries, nil
}

// Get opens one report.
func (v *Vault) Get(id string) (Record, error) {
	if !validID(id) {
		return Record{}, ErrNotFound
	}
	gcm, err := v.cipher()
	if err != nil {
		return Record{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.open(gcm, id)
}

// Delete removes one report for good.
func (v *Vault) Delete(id string) error {
	if !validID(id) {
		return ErrNotFound
	}
	if _, err := v.cipher(); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := os.Remove(v.path(id)); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("the report could not be deleted: %w", err)
	}
	return nil
}

// entries opens every report and keeps what the list shows. A file that does
// not open under this key is skipped: it was sealed under another one, or it
// is not a report.
func (v *Vault) entries(gcm cipher.AEAD) ([]Entry, error) {
	names, err := os.ReadDir(v.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("the history could not be read: %w", err)
	}
	var out []Entry
	for _, n := range names {
		id, ok := strings.CutSuffix(n.Name(), suffix)
		if !ok || !validID(id) {
			continue
		}
		r, err := v.open(gcm, id)
		if err != nil {
			continue
		}
		out = append(out, r.Entry)
	}
	return out, nil
}

func (v *Vault) open(gcm cipher.AEAD, id string) (Record, error) {
	body, err := os.ReadFile(v.path(id))
	if err != nil {
		return Record{}, ErrNotFound
	}
	if len(body) < gcm.NonceSize() {
		return Record{}, ErrNotFound
	}
	plain, err := gcm.Open(nil, body[:gcm.NonceSize()], body[gcm.NonceSize():], []byte(sealBase+id))
	if err != nil {
		return Record{}, ErrNotFound
	}
	var r Record
	if err := json.Unmarshal(plain, &r); err != nil || r.ID != id {
		return Record{}, ErrNotFound
	}
	return r, nil
}

// write seals body under id and puts it in place by a rename, so a report is
// never half-written.
func (v *Vault) write(gcm cipher.AEAD, id string, body []byte) error {
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("a nonce could not be generated: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, body, []byte(sealBase+id))

	tmp, err := os.CreateTemp(v.Dir, ".report-*")
	if err != nil {
		return fmt.Errorf("the report could not be kept: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the report could not be kept: %w", err)
	}
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("the report could not be kept: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("the report could not be kept: %w", err)
	}
	if err := os.Rename(name, v.path(id)); err != nil {
		return fmt.Errorf("the report could not be kept: %w", err)
	}
	return nil
}

func (v *Vault) cipher() (cipher.AEAD, error) {
	if v == nil || v.Key == nil {
		return nil, ErrLocked
	}
	key := v.Key()
	if len(key) != 32 {
		return nil, ErrLocked
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (v *Vault) path(id string) string { return filepath.Join(v.Dir, id+suffix) }

func (v *Vault) today() string {
	if v.Today != nil {
		return v.Today()
	}
	return time.Now().UTC().Format("2006-01-02")
}

// validID accepts the names this package makes and nothing else, so an
// identifier from a request cannot name a path.
// The seal binds the name as well, so this is not the only thing standing
// between a request and a path; it is the first.
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && id == strings.ToLower(id)
}

func sortNewestFirst(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Date != entries[j].Date {
			return entries[i].Date > entries[j].Date
		}
		return entries[i].Seq > entries[j].Seq
	})
}
