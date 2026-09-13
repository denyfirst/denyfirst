// Package ctlogs holds the certificate transparency logs a receipt can be
// checked against, and checks it.
//
// # Where the list comes from, and why a copy is carried
//
// A receipt — a signed certificate timestamp — is a log's signature over a
// certificate. Checking it needs the log's public key, and the keys are
// published by the browsers that decide which logs count. This package carries
// Chrome's list, byte for byte as Google publishes it at
// https://www.gstatic.com/ct/log_list/v3/log_list.json, together with the
// signature Google publishes beside it.
//
// This project argued for a long time against carrying a copy, and the argument
// was that a copy is a dependency on somebody else's judgement that goes stale
// between releases. Both halves are answered rather than ignored:
//
//   - **Somebody else's judgement.** The list is not edited, filtered or
//     re-typed here. It is Google's file, and it is only believed if Google's
//     signature over it verifies against a key written into this source — not
//     a key fetched alongside the list, which would make the signature
//     worthless. A test verifies the carried copy on every run, so a list
//     changed by hand in this repository fails the build.
//   - **Stale.** Every report names the list's own date, so a reader can see
//     how old the judgement is. A receipt from a log the list does not name is
//     said to be unverifiable against the list of that date — never that it is
//     false. And a weekly job compares the carried logs with the published ones
//     and opens an issue when they differ; see refresh/.
//
// # What is not done
//
// Nothing is graded. How many receipts a certificate needs, and from which
// logs, is each browser's policy (R21). What changes is that a receipt can now
// be said to be genuine rather than merely present.
package ctlogs

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"sync"
	"time"
)

// The carried list and its signature, exactly as published.
//
//go:embed log_list.json
var listJSON []byte

//go:embed log_list.sig
var listSignature []byte

// googleListKey is the key Google signs the log list with, as published at
// https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem.
//
// Written into the source on purpose. A key downloaded beside the list it
// verifies proves only that whoever served the list also served a key, which is
// what an attacker able to replace one would do with the other.
const googleListKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv
HHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq
fUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L
rmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+
i/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF
bLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S
IXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox
K0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe
/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF
4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+
+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS
1w22i9uGHMn/uGQKo28u7AsCAwEAAQ==
-----END PUBLIC KEY-----
`

// ListSource is where the carried list is published.
const ListSource = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// SignatureSource is where its signature is published.
const SignatureSource = "https://www.gstatic.com/ct/log_list/v3/log_list.sig"

// maxLogs bounds what a list can make this hold.
const maxLogs = 1024

// ErrSignature means a list's signature did not verify, so nothing in it is
// believed.
var ErrSignature = errors.New("ctlogs: the log list's signature does not verify")

var errUnreadable = errors.New("ctlogs: the log list could not be read")

// Log is one log the list names.
type Log struct {
	ID          [32]byte
	Key         crypto.PublicKey
	Description string
	Operator    string

	// State is what the list says of the log: usable, qualified, readonly,
	// retired, rejected or pending. Reported, never used to discount a
	// receipt — a receipt from a retired log was issued while it counted.
	State string

	// Tiled is true for a log in the static-ct family.
	Tiled bool
}

// List is a verified log list.
type List struct {
	Version   string
	Timestamp time.Time
	logs      map[[32]byte]Log
}

// Log looks a log up by the identifier a receipt carries.
func (l *List) Log(id [32]byte) (Log, bool) {
	if l == nil {
		return Log{}, false
	}
	log, ok := l.logs[id]
	return log, ok
}

// Len is how many logs the list names.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.logs)
}

// Summary is one line per log — identifier and state — sorted, so two lists
// can be compared by what matters and not by a version number that moves daily.
func (l *List) Summary() []string {
	if l == nil {
		return nil
	}
	out := make([]string, 0, len(l.logs))
	for id, log := range l.logs {
		out = append(out, hex.EncodeToString(id[:])+" "+log.State)
	}
	sort.Strings(out)
	return out
}

// Difference is what one list says that the other does not, as Summary lines:
// added are in next and not in current, removed the reverse. A log whose state
// changed appears once in each.
func Difference(current, next *List) (added, removed []string) {
	inCurrent := map[string]bool{}
	for _, line := range current.Summary() {
		inCurrent[line] = true
	}
	inNext := map[string]bool{}
	for _, line := range next.Summary() {
		inNext[line] = true
		if !inCurrent[line] {
			added = append(added, line)
		}
	}
	for _, line := range current.Summary() {
		if !inNext[line] {
			removed = append(removed, line)
		}
	}
	return added, removed
}

var (
	embeddedOnce sync.Once
	embedded     *List
	embeddedErr  error
)

// Embedded is the carried list, verified once.
//
// An error means the copy in this build did not verify, and every receipt is
// then unverifiable rather than checked against an unbelieved list.
func Embedded() (*List, error) {
	embeddedOnce.Do(func() {
		embedded, embeddedErr = Parse(listJSON, listSignature)
	})
	return embedded, embeddedErr
}

// Parse verifies a list against Google's key and reads it.
//
// The signature is checked before a byte of the list is parsed. What an
// attacker can make a JSON parser do with bytes nobody vouched for is not a
// question worth having an answer to.
func Parse(list, signature []byte) (*List, error) {
	block, _ := pem.Decode([]byte(googleListKey))
	if block == nil {
		return nil, errUnreadable
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errUnreadable
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errUnreadable
	}

	digest := sha256.Sum256(list)
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, ErrSignature
	}
	return read(list)
}

// read parses a list whose signature has already been verified.
//
// Separate from Parse so that a test can hand it lists no key ever signed —
// which is the only way to reach the checks below, since a list that reaches
// them in production has already been vouched for.
func read(list []byte) (*List, error) {
	var raw struct {
		Version   string `json:"version"`
		Timestamp string `json:"log_list_timestamp"`
		Operators []struct {
			Name  string   `json:"name"`
			Logs  []rawLog `json:"logs"`
			Tiled []rawLog `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(list, &raw); err != nil {
		return nil, errUnreadable
	}

	out := &List{Version: raw.Version, logs: map[[32]byte]Log{}}
	if ts, err := time.Parse(time.RFC3339, raw.Timestamp); err == nil {
		out.Timestamp = ts
	}

	add := func(operator string, r rawLog, tiled bool) error {
		if len(out.logs) >= maxLogs {
			return errUnreadable
		}
		id, err := base64.StdEncoding.DecodeString(r.LogID)
		if err != nil || len(id) != 32 {
			return errUnreadable
		}
		keyDER, err := base64.StdEncoding.DecodeString(r.Key)
		if err != nil {
			return errUnreadable
		}
		pub, err := x509.ParsePKIXPublicKey(keyDER)
		if err != nil {
			return errUnreadable
		}

		// A log's identifier is the hash of its key (RFC 6962 §3.2). A list
		// pairing an identifier with some other key would let a receipt be
		// checked against a key its log never held.
		if sha256.Sum256(keyDER) != [32]byte(id) {
			return errUnreadable
		}

		out.logs[[32]byte(id)] = Log{
			ID: [32]byte(id), Key: pub, Description: r.Description,
			Operator: operator, State: r.state(), Tiled: tiled,
		}
		return nil
	}

	for _, op := range raw.Operators {
		for _, r := range op.Logs {
			if err := add(op.Name, r, false); err != nil {
				return nil, err
			}
		}
		for _, r := range op.Tiled {
			if err := add(op.Name, r, true); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

type rawLog struct {
	Description string                     `json:"description"`
	LogID       string                     `json:"log_id"`
	Key         string                     `json:"key"`
	State       map[string]json.RawMessage `json:"state"`
}

// state is the one key of the state object, which is how the list writes it.
func (r rawLog) state() string {
	for name := range r.State {
		return name
	}
	return "unknown"
}
