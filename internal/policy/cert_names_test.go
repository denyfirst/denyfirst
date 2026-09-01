package policy

import (
	"strings"
	"testing"
	"time"
)

var certNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// An ordinary certificate from a public authority. Every case below starts
// here and changes one thing, so a rule that fires is firing for the thing
// that changed.
func ordinaryLeaf() LeafFacts {
	return LeafFacts{
		NotBefore:          certNow.Add(-30 * 24 * time.Hour),
		NotAfter:           certNow.Add(60 * 24 * time.Hour),
		KeyAlgorithm:       "ECDSA",
		KeyBits:            256,
		SignatureAlgorithm: "ECDSA-SHA256",
		HasSAN:             true,
		SelfSigned:         false,
		ChainTrusted:       true,
		ChainComplete:      true,
		HostnameMatches:    true,
		SerialBits:         64,
		CommonName:         "example.com",
		DNSNames:           []string{"example.com", "www.example.com"},
		HasExtKeyUsage:     true,
		ServerAuth:         true,

		// What an ordinary subscriber certificate says it may be and do: not
		// an authority, and permitted to sign, which every TLS 1.3 and every
		// ECDHE handshake needs.
		BasicConstraintsValid: true,
		IsCA:                  false,
		HasKeyUsage:           true,
		DigitalSignature:      true,
	}
}

func fires(f LeafFacts, ruleID string) bool {
	for _, finding := range GradeLeaf(f, certNow).Findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

// The direction that matters most for every rule at once: a correct
// certificate is accused of nothing new.
func TestAnOrdinaryCertificateRaisesNoneOfTheNewRules(t *testing.T) {
	for _, rule := range []string{
		"cert.no-server-auth", "cert.wildcard-shape", "cert.cn-not-in-san", "cert.serial-entropy",
		"cert.leaf-is-ca", "cert.key-usage-cert-sign", "cert.no-digital-signature",
		"cert.critical-extension-unrecognised",
	} {
		if fires(ordinaryLeaf(), rule) {
			t.Errorf("%s fires against an ordinary certificate", rule)
		}
	}
}

// Absent is not the same as excluding.
//
// A certificate with no extended key usage extension may be used for any
// purpose, which RFC 5280 permits and which older certificates commonly do.
// One that lists purposes has listed all of them, and a list without server
// authentication is a certificate for something else.
func TestAnExtendedKeyUsageWithoutServerAuth(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*LeafFacts)
		accused bool
	}{
		{"lists server authentication", func(f *LeafFacts) {}, false},
		{"lists other purposes only", func(f *LeafFacts) { f.ServerAuth = false }, true},
		{"lists nothing at all", func(f *LeafFacts) {
			f.HasExtKeyUsage = false
			f.ServerAuth = false
		}, false},
	}

	for _, c := range cases {
		facts := ordinaryLeaf()
		c.change(&facts)
		if got := fires(facts, "cert.no-server-auth"); got != c.accused {
			t.Errorf("%s: accused=%v, want %v", c.name, got, c.accused)
		}
	}
}

// A wildcard is the whole of the leftmost label or it is nothing.
//
// Every shape below was matched by some client at some point and is matched by
// none now, so a name in one of them covers nothing while looking as though it
// covers something — which is worse than a name that is plainly absent,
// because whoever issued it believes the host is covered.
func TestOnlyAWholeLeftmostLabelIsAWildcard(t *testing.T) {
	cases := []struct {
		names   []string
		accused bool
	}{
		{[]string{"example.com", "www.example.com"}, false},
		{[]string{"*.example.com"}, false},
		{[]string{"*.a.example.com"}, false},
		{[]string{"example.com", "*.example.com"}, false},

		{[]string{"w*.example.com"}, true},
		{[]string{"*w.example.com"}, true},
		{[]string{"a.*.example.com"}, true},
		{[]string{"*.*.example.com"}, true},
		{[]string{"*"}, true},
		{[]string{"*.com"}, true},
		{[]string{"example.com", "w*.example.com"}, true},
	}

	for _, c := range cases {
		facts := ordinaryLeaf()
		facts.CommonName = ""
		facts.DNSNames = c.names
		if got := fires(facts, "cert.wildcard-shape"); got != c.accused {
			t.Errorf("%v: accused=%v, want %v", c.names, got, c.accused)
		}
	}
}

// The common name is read by people and matched by nothing.
//
// It is only worth a finding when it is trying to be a hostname. An
// authority's own certificate carries something like "R11" and an older leaf
// carries an organisation; reading either as a hostname absent from the
// extension would be an accusation about a field that never claimed to be one.
func TestACommonNameThatIsNotAmongTheNames(t *testing.T) {
	cases := []struct {
		name    string
		cn      string
		names   []string
		accused bool
	}{
		{"repeats a name", "example.com", []string{"example.com"}, false},
		{"repeats it in another case", "EXAMPLE.com", []string{"example.com"}, false},
		{"names a host that is not there", "example.com", []string{"www.example.com"}, true},
		{"is empty", "", []string{"example.com"}, false},
		{"is an authority's label", "R11", []string{"example.com"}, false},
		{"is an organisation", "Example Ltd, London", []string{"example.com"}, false},

		// A wildcard in the extension does not put the common name in it. The
		// Baseline Requirements ask for one of the values, not for a value
		// something else would match.
		{"is covered by a wildcard rather than listed", "www.example.com",
			[]string{"*.example.com"}, true},
	}

	for _, c := range cases {
		facts := ordinaryLeaf()
		facts.CommonName = c.cn
		facts.DNSNames = c.names
		if got := fires(facts, "cert.cn-not-in-san"); got != c.accused {
			t.Errorf("%s: accused=%v, want %v", c.name, got, c.accused)
		}
	}
}

// The serial threshold, and the arithmetic behind it.
//
// A serial carrying 64 bits from a random source is uniform over [0, 2^64), so
// its value has fewer than 64 bits half the time. A rule demanding 64 would
// accuse half of every compliant certificate ever issued, which is why this
// one demands far less and says far less.
func TestASerialTooSmallToBeRandom(t *testing.T) {
	cases := []struct {
		name    string
		bits    int
		trusted bool
		accused bool
	}{
		{"sixty-four bits", 64, true, false},
		{"sixty-three bits, which half of compliant serials are", 63, true, false},
		{"thirty-two bits", 32, true, false},
		{"thirty-one bits", 31, true, true},
		{"a counter", 8, true, true},
		// Zero means nobody read it, not that it is zero. A rule that fires
		// here is drawing a measurement that did not happen, which is what
		// R12 is about and what the existing tests in this package caught
		// this rule doing on its first run. A serial that really is not
		// positive is reported as a note by certinfo instead.
		{"a serial nobody measured", 0, true, false},

		// The requirement is the CA/Browser Forum's, and a private authority
		// answers to whoever runs it. A sequential serial from an internal CA
		// is how internal CAs work.
		{"a counter from an authority nobody public trusts", 8, false, false},
	}

	for _, c := range cases {
		facts := ordinaryLeaf()
		facts.SerialBits = c.bits
		facts.ChainTrusted = c.trusted
		if got := fires(facts, "cert.serial-entropy"); got != c.accused {
			t.Errorf("%s: accused=%v, want %v", c.name, got, c.accused)
		}
	}
}

// Each new rule states a reason, and the reason has to name what was found.
func TestTheNewFindingsSayWhatTheyFound(t *testing.T) {
	facts := ordinaryLeaf()
	facts.SerialBits = 8
	facts.ServerAuth = false
	facts.CommonName = "elsewhere.example"
	facts.DNSNames = []string{"example.com", "w*.example.com"}

	want := map[string]string{
		"cert.serial-entropy": "8 bits",
		"cert.no-server-auth": "server authentication",
		"cert.cn-not-in-san":  "elsewhere.example",
		"cert.wildcard-shape": "w*.example.com",
	}

	seen := map[string]bool{}
	for _, finding := range GradeLeaf(facts, certNow).Findings {
		fragment, watched := want[finding.RuleID]
		if !watched {
			continue
		}
		seen[finding.RuleID] = true
		if !strings.Contains(finding.Rationale, fragment) {
			t.Errorf("%s does not name %q in its reason:\n  %s", finding.RuleID, fragment, finding.Rationale)
		}
	}
	for rule := range want {
		if !seen[rule] {
			t.Errorf("%s did not fire against facts written to trigger it", rule)
		}
	}
}

// A server cannot make its own finding large.
//
// Every name a rule quotes is chosen by the server being examined, which on a
// hostile target means it is chosen by the target. internal/certinfo bounds
// what reaches the report for display and says why: passing it through
// unbounded turns one small request into a reply measured in megabytes, paid
// for by whoever asked for the scan rather than by the server that sent it.
//
// These rules decide on the whole list and quote part of it, and until
// 2026-09-01 they quoted all of it. Measured then: a certificate carrying five
// thousand malformed names produced one finding of 1,085,200 bytes.
func TestAFindingCannotBeMadeHugeByTheServerItDescribes(t *testing.T) {
	var many []string
	for i := 0; i < 5000; i++ {
		many = append(many, strings.Repeat("a", 200)+"*.example.com")
	}

	facts := ordinaryLeaf()
	facts.DNSNames = many
	facts.CommonName = strings.Repeat("b", 5000) + ".example.com"

	const ceiling = 2048
	for _, finding := range GradeLeaf(facts, certNow).Findings {
		if len(finding.Rationale) > ceiling {
			t.Errorf("%s is %d bytes, which a server chose. The bound is %d.",
				finding.RuleID, len(finding.Rationale), ceiling)
		}
	}

	// Bounded and still honest: the count that was not shown is said.
	var wildcard string
	for _, finding := range GradeLeaf(facts, certNow).Findings {
		if finding.RuleID == "cert.wildcard-shape" {
			wildcard = finding.Rationale
		}
	}
	if wildcard == "" {
		t.Fatal("the wildcard rule did not fire against five thousand malformed names")
	}
	if !strings.Contains(wildcard, "4995 more") {
		t.Errorf("the finding quotes five names and does not say how many it left out:\n%s", wildcard)
	}
}

// A name is bytes the server chose, and a terminal reads some of those bytes
// as instructions.
//
// certinfo makes this argument for the subject one round earlier: a
// certificate carrying an escape sequence can erase the verdict printed above
// it. The same bytes reach a sentence here, and quoting is what stops them.
func TestANameCannotCarryAnEscapeSequenceIntoAFinding(t *testing.T) {
	facts := ordinaryLeaf()
	facts.CommonName = "\x1b[2K\x1b[1Aelsewhere.example"
	facts.DNSNames = []string{"\x1b[2Kw*.example.com", "example.com"}

	for _, finding := range GradeLeaf(facts, certNow).Findings {
		if strings.ContainsAny(finding.Rationale, "\x1b\x00\r\n\a\b") {
			t.Errorf("%s carries a control byte the server chose:\n%q", finding.RuleID, finding.Rationale)
		}
	}
}
