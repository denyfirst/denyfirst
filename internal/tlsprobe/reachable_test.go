package tlsprobe

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/rawhello"
)

// A rule this front end can never reach is not coverage, and it is named here
// rather than counted.
//
// The Known gaps list said this of one rule, `cipher.ffdhe`, because somebody
// noticed. Measuring it found nine: of the thirteen cipher rules, four can
// fire against a server and nine cannot, because Go implements no suite that
// matches them. Nobody had counted, and a list that names one case out of nine
// reads as though the other eight do not exist.
//
// Only versions and cipher suites are decidable here, and that is the point of
// putting this test in this package: what can be graded is bounded by what
// this prober offers, and this package is what offers it. A certificate rule
// depends on the certificate a server chooses to present, which nothing here
// can enumerate — claiming to have measured that would be the kind of false
// completeness this test exists to prevent.
//
// Six left this list on 2026-09-13 — version.ssl3, cipher.null, cipher.export,
// cipher.anonymous, cipher.des and cipher.ffdhe — when SSL 3.0 and the export
// and NULL suites began to be asked about with a hand-written hello. Two of
// those six are reachable only narrowly, and the Known gaps say how.
var unreachableThroughThisFrontEnd = map[string]string{
	"version.unknown": "probedVersions is a fixed list and a hand-written hello rejects any version it did not claim, " +
		"so no version outside the known ones can come back",

	"cipher.no-encryption": "neither Go nor a hand-written hello offers an RFC 9150 integrity-only suite",
	"cipher.md5": "every MD5 suite offered by hand is matched first by a more specific rule — " +
		"NULL, export or RC4 — so the MD5 rule is shadowed",

	"cipher.unrecognised": "every suite offered is one this build of Go names, so a suite it cannot describe " +
		"cannot come back from an enumeration that only offers named ones",
	"cipher.not-current-practice": "reachable in principle and shadowed in practice: GradeCipher stops at the " +
		"first matching rule, and for all twenty-two suites this prober can offer a more specific rule matches first",
}

// reachableRules grades everything this prober is able to offer and collects
// the rule ids that come back.
func reachableRules(t *testing.T) map[string]bool {
	t.Helper()

	names := map[uint16]string{}
	for _, s := range tls.CipherSuites() {
		names[s.ID] = s.Name
	}
	for _, s := range tls.InsecureCipherSuites() {
		names[s.ID] = s.Name
	}

	reachable := map[string]bool{}
	for _, v := range probedVersions {
		for _, f := range policy.GradeVersion(v).Findings {
			reachable[f.RuleID] = true
		}
		for _, id := range candidateSuites(v) {
			name, known := names[id]
			if !known {
				t.Fatalf("suite %#04x is offered and this build of Go does not name it", id)
			}
			for _, f := range policy.GradeCipher(name).Findings {
				reachable[f.RuleID] = true
			}
		}
	}

	// And what the hand-written hellos offer, which is what Go cannot. Graded
	// exactly the way askLegacy grades an answer, so a rule reachable here is a
	// rule a real reply can raise.
	for _, f := range policy.GradeVersion(policy.VersionSSL30).Findings {
		reachable[f.RuleID] = true
	}
	for _, list := range [][]rawhello.Suite{rawhello.SSL3, rawhello.Export, rawhello.Null} {
		for _, s := range list {
			for _, f := range policy.GradeCipher(s.Name).Findings {
				reachable[f.RuleID] = true
			}
		}
	}
	return reachable
}

// declaredRules reads every rule id the policy package can emit out of its own
// source.
//
// Scanning the source rather than asking the package, because there is no list
// to ask for: cipher rules come from a table and version rules from literals
// in a switch. A list maintained by hand beside the rules is a list that goes
// stale, and going stale silently is the failure this whole test is about.
func declaredRules(t *testing.T, prefixes ...string) []string {
	t.Helper()

	files, err := filepath.Glob("../policy/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("finding the policy sources: %v", err)
	}

	// Both spellings: `id:` in the cipher rule table, `RuleID:` in the
	// findings built inline.
	pattern := regexp.MustCompile(`(?:RuleID|id):\s*"([a-z]+\.[a-z0-9-]+)"`)

	seen := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range pattern.FindAllStringSubmatch(string(body), -1) {
			for _, prefix := range prefixes {
				if strings.HasPrefix(m[1], prefix) {
					seen[m[1]] = true
				}
			}
		}
	}

	var out []string
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no rule ids were found in the policy sources, so this test asserts nothing")
	}
	return out
}

// Every version and cipher rule either fires against something this prober can
// offer, or is named as one that cannot. There is no third case.
func TestEveryGradingRuleIsReachableOrNamed(t *testing.T) {
	reachable := reachableRules(t)

	for _, id := range declaredRules(t, "version.", "cipher.") {
		_, named := unreachableThroughThisFrontEnd[id]
		switch {
		case reachable[id] && named:
			t.Errorf("%s is listed as unreachable and it fires against a suite or version this prober "+
				"offers. Remove it from the list and from the Known gaps in docs/invariants.md: a stale "+
				"gap reads as current and hides that the rule now works.\n  listed reason: %s",
				id, unreachableThroughThisFrontEnd[id])
		case !reachable[id] && !named:
			t.Errorf("%s can never fire through this front end and is not named as such. Either give this "+
				"prober something that reaches it, or add it to unreachableThroughThisFrontEnd with the "+
				"reason and to the Known gaps in docs/invariants.md. A rule that cannot fire is not "+
				"coverage, and counting it as coverage is how a scanner comes to claim more than it does.", id)
		}
	}
}

// A gap named in code and not in the document is a gap the reader cannot find.
//
// docs/invariants.md is where this project says what it does not do, and the
// list above is where the code says it. They are two statements of one fact,
// and the one nobody reads is the one that rots.
func TestEveryUnreachableRuleIsInTheKnownGaps(t *testing.T) {
	body, err := os.ReadFile("../../docs/invariants.md")
	if err != nil {
		t.Fatalf("reading docs/invariants.md: %v", err)
	}
	page := string(body)

	for id := range unreachableThroughThisFrontEnd {
		if !strings.Contains(page, "`"+id+"`") {
			t.Errorf("%s is named unreachable in this package and nowhere in docs/invariants.md. "+
				"A reader looking for what this scanner cannot see will not find it.", id)
		}
	}
}
