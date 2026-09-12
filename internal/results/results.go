// Package results keeps a deployment's own scans, when it is asked to.
//
// This project records nothing about a scan by default and that is the promise
// it is built on. The promise was never "storage is bad": it was that
// denyfirst.dev is the visible party in somebody else's logs and cannot say who
// asked, so holding other people's scanning behaviour would make it a
// repository worth seizing. None of that reasoning survives the move to an
// installation somebody runs themselves — there the scans are of their own
// estate, on their own machine, because they asked.
//
// So the promise is stated the way it is actually true:
//
//	This installation holds nothing about anyone but you.
//
// On the demonstration nothing is stored at all, and that stays absolute.
// Elsewhere what is stored is the report that was already produced, written
// where the operator said to write it, and only because they said so.
//
// # What this deliberately does not do
//
// **It is not served over HTTP.** A service with a browsable history of an
// estate's weaknesses is a thing worth attacking, and porchd has no
// authentication at all. Reading the store back is the command line's job,
// which runs on the operator's own machine and exposes nothing to a network.
// Offering it over HTTP is a separate decision with an authentication system
// attached, and one made deliberately rather than as a side effect of being
// able to write files.
//
// **It invents no retention period.** A number this project chose would be a
// threshold nobody can argue with, which is the failure R21 is written about,
// applied to somebody's disk instead of to their configuration. Keep is the
// operator's to set; unset keeps everything and says so.
//
// **It stores no more than a report already carries.** The same JSON, which has
// nowhere to put markup, a cookie's value, a client address or a time beyond a
// date. Writing it down does not relax what a report may contain.
package results

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// maxLine bounds one stored record on the way back in.
	//
	// A file on the operator's own disk, so this is not a defence against them.
	// It is a bound on what a corrupted or hand-edited file can make this
	// program allocate, which is the same reason every other reader here has
	// one.
	maxLine = 1 << 20

	// dirMode and fileMode keep the store to its owner.
	//
	// A history of an estate's weaknesses is the most useful thing on the
	// machine to somebody who should not have it, and a scanner that wrote it
	// world-readable would have handed over the map it exists to draw.
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// Record is one scan, kept.
type Record struct {
	// Date is the day the scan ran, and the whole of what is kept about when.
	//
	// Not a timestamp. The project's retention language is "nothing beyond a
	// date" and this is the operator's own machine, so a finer grain would be
	// recording something nobody asked for in a file nobody expected to hold
	// it. A day is enough to answer "is this better than last month".
	Date string `json:"date"`

	// Check names which of the three produced it, because the three rule sets
	// are not comparable with each other.
	Check string `json:"check"`

	// Policy is the rule set that graded it. Kept beside the verdict rather
	// than inferred later: a history spanning a rule-set change holds verdicts
	// that are not comparable, and only this says where the line falls.
	Policy string `json:"policy"`

	// Verdict is what it was graded. Empty means nothing was established,
	// which is not passing (R4).
	Verdict string `json:"verdict,omitempty"`

	// Findings are the rule identifiers raised, which is what a reader
	// compares between two dates. The prose is free to improve; these are
	// stable across releases and are what a diff should rest on.
	Findings []string `json:"findings,omitempty"`
}

// Store writes and reads one deployment's scans.
//
// The zero value stores nothing, which is what every caller that has not been
// told where to write gets. A nil *Store is usable and does the same, so a
// caller need not branch.
type Store struct {
	// Dir is where records are written. Empty stores nothing.
	Dir string

	// Keep bounds how many records are held for one target and check. Zero or
	// negative keeps everything.
	Keep int

	// Now supplies the date, so a test is not at the mercy of midnight.
	Now func() time.Time
}

// Enabled reports whether anything is being kept.
func (s *Store) Enabled() bool { return s != nil && s.Dir != "" }

// Put appends one record.
//
// A failure here is reported and never fatal. The scan already happened and the
// report is already in the operator's hands; losing the copy is worth a line on
// stderr and is not worth failing a check that succeeded.
func (s *Store) Put(check, target string, verdict, policy string, findings []string) error {
	if !s.Enabled() {
		return nil
	}

	path, err := s.pathFor(check, target)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}

	record := Record{
		Date:     s.today(),
		Check:    check,
		Policy:   policy,
		Verdict:  verdict,
		Findings: findings,
	}

	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(line)+1 > maxLine {
		return errors.New("results: a record is larger than the store will hold")
	}

	// #nosec G304 -- the path is built from an operator-supplied directory and
	// a target this package has already checked is a bare name.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close() //nolint:errcheck,gosec // the write error is the one worth reporting
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return s.trim(path)
}

// History returns what is held for one target and check, oldest first.
//
// A store that holds nothing and a target that was never scanned are the same
// answer here, and the caller says which it means: this package cannot tell
// "you keep no records" from "you have not scanned this" and should not guess.
func (s *Store) History(check, target string) ([]Record, error) {
	if !s.Enabled() {
		return nil, nil
	}

	path, err := s.pathFor(check, target)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- as above.
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return parse(body), nil
}

// parse reads records, skipping any line that is not one.
//
// A file somebody edited by hand, or one a full disk truncated mid-write, is
// still worth reading the rest of. Refusing the whole history because its last
// line is half-written would lose everything to the one failure most likely to
// happen.
func parse(body []byte) []Record {
	var out []Record
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || len(line) > maxLine {
			continue
		}

		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

// trim drops the oldest records once there are more than Keep.
func (s *Store) trim(path string) error {
	if s.Keep <= 0 {
		return nil
	}

	// #nosec G304 -- as above.
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	records := parse(body)
	if len(records) <= s.Keep {
		return nil
	}

	var rebuilt strings.Builder
	for _, r := range records[len(records)-s.Keep:] {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		rebuilt.Write(line)
		rebuilt.WriteByte('\n')
	}

	return os.WriteFile(path, []byte(rebuilt.String()), fileMode)
}

// pathFor builds the file one target's history lives in.
//
// The target is in the filename, which makes a store something an operator can
// look through with the tools they already have. That is only safe because the
// name is checked first: a path is assembled here, and a target carrying a
// separator or a parent reference would write outside the directory the
// operator named. Checked rather than escaped, for the reason this project
// checks hostnames everywhere else — an allow list cannot be surprised by
// something nobody thought to forbid.
func (s *Store) pathFor(check, target string) (string, error) {
	// An empty directory is refused here as well as by Enabled.
	//
	// Not belt and braces for its own sake. filepath.Join("", "tls", x) is a
	// relative path, so a store that reached this with no directory would write
	// into whatever the program was started from — which for a service is
	// wherever systemd left it, and for a container is /. A sabotage on
	// 2026-09-12 broke Enabled and the store immediately wrote a file into the
	// source tree, which is the harmless version of the same mistake.
	if s.Dir == "" {
		return "", errors.New("results: no directory was given, so there is nowhere to keep this")
	}

	if err := safeName(check); err != nil {
		return "", fmt.Errorf("results: the check name is not one: %w", err)
	}
	if err := safeName(target); err != nil {
		return "", fmt.Errorf("results: the target is not a bare name: %w", err)
	}
	return filepath.Join(s.Dir, check, target+".jsonl"), nil
}

var errNotAName = errors.New("it must be letters, digits, dots, hyphens and underscores")

// safeName refuses anything that is not a bare name.
func safeName(name string) error {
	if name == "" || len(name) > 253 {
		return errNotAName
	}
	if name == "." || name == ".." || strings.Contains(name, "..") {
		return errNotAName
	}

	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return errNotAName
		}
	}
	return nil
}

func (s *Store) today() string {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return now().UTC().Format("2006-01-02")
}
