package policy

import (
	"crypto/tls"
	"strings"
	"testing"
)

// A value does not repeat the heading it is printed under.
//
// Every suite in a report is printed under the protocol version it was
// accepted at — the web page groups by version, the command line groups by
// version, and the JSON nests the suites inside the version. So a key exchange
// that reads "ephemeral (TLS 1.3)" prints the words "TLS 1.3" again on every
// row of a table already headed "TLS 1.3", and the parenthesis is not the
// reason for the value, only the heading a second time.
//
// This is a naming rule and not a display rule, so it is enforced where the
// name is made rather than in one of the two places it is shown. Both faces
// then agree without either of them being asked to.
func TestACipherDescriptionDoesNotRepeatItsProtocolVersion(t *testing.T) {
	names := []string{
		// RFC 9150. The standard library has no name for these, and they are
		// the only TLS 1.3 suites whose properties are not covered by the
		// branch every other one takes.
		"TLS_SHA256_SHA256",
		"TLS_SHA384_SHA384",
	}
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		names = append(names, tls.CipherSuiteName(s.ID))
	}
	// A name the library has no entry for, so the default branch is covered.
	names = append(names, tls.CipherSuiteName(0x1234))

	if len(names) < 20 {
		t.Fatalf("only %d suite names were gathered, which is too few to be right", len(names))
	}

	for _, name := range names {
		p := DescribeCipher(name)
		for label, value := range map[string]string{
			"key exchange": p.KeyExchange,
			"cipher":       p.Cipher,
		} {
			for _, version := range []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "SSL "} {
				if strings.Contains(value, version) {
					t.Errorf("the %s of %s is %q, which repeats the heading it is printed under",
						label, name, value)
				}
			}
		}
		if strings.TrimSpace(p.KeyExchange) == "" {
			t.Errorf("%s has no key exchange at all", name)
		}
		if strings.TrimSpace(p.Cipher) == "" {
			t.Errorf("%s has no cipher at all", name)
		}
	}
}

// Every TLS 1.3 suite says the same thing about its key exchange, and says it
// in one word.
//
// The suite name in TLS 1.3 carries the AEAD and the hash and nothing else:
// the group is chosen in an extension, and RFC 9846 removed static exchange
// from the protocol. So "ephemeral" is a property of the version rather than
// of the suite, and every one of them has to report it identically — a table
// where one row said something else would be claiming a measurement that was
// never made.
func TestEveryTLS13SuiteReportsTheSameKeyExchange(t *testing.T) {
	seen := map[string][]string{}
	for _, s := range tls.CipherSuites() {
		name := tls.CipherSuiteName(s.ID)
		if !isTLS13Suite(name) {
			continue
		}
		k := DescribeCipher(name).KeyExchange
		seen[k] = append(seen[k], name)
	}
	if len(seen) == 0 {
		t.Fatal("no TLS 1.3 suites were found")
	}
	if len(seen) != 1 {
		t.Errorf("TLS 1.3 suites report %d different key exchanges: %v", len(seen), seen)
	}
	if _, ok := seen["ephemeral"]; !ok {
		t.Errorf("TLS 1.3 suites report %v rather than \"ephemeral\"", seen)
	}
}
