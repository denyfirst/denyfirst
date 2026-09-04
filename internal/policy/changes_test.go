package policy

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A document describing what a policy version changed is worth exactly its
// currency.
//
// Verdicts carry the name of the rule set that produced them precisely so
// that two reports can be compared, and a reader who finds a server graded
// differently this month goes looking for what moved. If the page describing
// that stops at the previous version, it answers the question wrongly rather
// than not at all — which this project has already caught itself doing on the
// Known gaps list.
//
// So the page has to name the version in force. Bumping Version without
// writing down what changed fails here.
func TestTheChangeLogCoversTheCurrentPolicy(t *testing.T) {
	body, err := os.ReadFile("../../docs/policy-changes.md")
	if err != nil {
		t.Fatalf("reading docs/policy-changes.md: %v", err)
	}

	for _, version := range []string{TLSVersion, WebVersion} {
		if !strings.Contains(string(body), version) {
			t.Errorf("docs/policy-changes.md does not mention %q. The rules moved and the page describing "+
				"what moved did not, so a reader comparing two reports is told the wrong thing.", version)
		}
	}
}

// Every rule identifier the change log names has to exist, for the same
// reason every invariant has to cite a test that exists: a page naming rules
// nobody can find is a page nobody can check.
func TestTheChangeLogNamesRulesThatExist(t *testing.T) {
	body, err := os.ReadFile("../../docs/policy-changes.md")
	if err != nil {
		t.Fatalf("reading docs/policy-changes.md: %v", err)
	}

	// Cipher rules are a table and can be read at run time. Certificate
	// rules are raised by name inside GradeLeaf, so the identifiers are
	// collected from the source instead. Both halves have to be covered: a
	// check over one of them would pass while the page invented rules in the
	// other.
	known := map[string]bool{}
	for _, rule := range cipherRules {
		known[rule.id] = true
	}

	quoted := regexp.MustCompile(`"((?:cipher|cert|chain|version)\.[a-z0-9-]+)"`)
	for _, file := range []string{"policy.go", "cert.go", "chain.go", "issuance.go", "staple.go", "transparency.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for _, m := range quoted.FindAllStringSubmatch(string(source), -1) {
			known[m[1]] = true
		}
	}

	for _, line := range strings.Split(string(body), "\n") {
		for _, token := range strings.Fields(line) {
			id := strings.Trim(token, "`|,.")
			if !strings.HasPrefix(id, "cipher.") && !strings.HasPrefix(id, "cert.") && !strings.HasPrefix(id, "chain.") {
				continue
			}
			if !known[id] {
				t.Errorf("docs/policy-changes.md names %q and no rule has that identifier", id)
			}
		}
	}
}

// A rule set that has shipped says which release shipped it.
//
// The page exists so that an operator whose server was graded differently
// this month can tell a configuration that got worse from a rule that got
// stricter, and the first thing that asks is *when*: which upgrade moved the
// rule set, so they know which reports to distrust.
//
// A section reading "Unreleased" answers that wrongly rather than not at all.
// On 2026-09-01 the `denyfirst-v3` → `denyfirst-v4` section still said it.
// v4 had been the rule set in production since v0.4.0 — five releases and
// three weeks earlier — because the line was written before that release and
// nobody re-reads a page whose newest section is correct. It is the same
// defect as an invariant citing a test that has been renamed: not a lie
// anybody told, just one nobody went back for.
//
// The section for the rule set in force may say either. It is written before
// the tag it names exists, which is the whole reason the stale line survived.
// Every older section has to name a release.
func TestEveryRuleSetThatShippedNamesItsRelease(t *testing.T) {
	body, err := os.ReadFile("../../docs/policy-changes.md")
	if err != nil {
		t.Fatalf("reading docs/policy-changes.md: %v", err)
	}
	page := string(body)

	// A rule set is named "denyfirst-v6" or "denyfirst-tls-v6": the check
	// segment appeared when this project stopped having exactly one check,
	// and the older names stay as they were because reports carrying them
	// exist and the page is a record of what shipped, not of what it would be
	// called today.
	number := regexp.MustCompile(`-v([0-9]+)$`)

	numberOf := func(name string) int {
		m := number.FindStringSubmatch(name)
		if m == nil {
			return 0
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0
		}
		return n
	}

	current := numberOf(TLSVersion)
	if current < 1 {
		t.Fatalf("policy version %q does not end in -vN, so this test cannot tell "+
			"a shipped rule set from the one in force", TLSVersion)
	}

	heading := regexp.MustCompile("(?m)^## `denyfirst-(?:[a-z]+-)?v[0-9]+` → `(denyfirst-(?:[a-z]+-)?v[0-9]+)`")
	found := heading.FindAllStringSubmatchIndex(page, -1)

	// The name each section introduces, and the prose under it. Keyed by the
	// whole name rather than by the number, because a rename introduces a new
	// name for a number that already had one.
	section := map[string]string{}
	for i, m := range found {
		name := page[m[2]:m[3]]
		end := len(page)
		if i+1 < len(found) {
			end = found[i+1][0]
		}
		section[name] = page[m[1]:end]
	}

	// A check that parses nothing passes everything. Every rule set from the
	// second to the one in force has a section, or the headings have drifted
	// out of the shape this test reads and it has stopped checking.
	covered := map[int]bool{}
	for name := range section {
		covered[numberOf(name)] = true
	}
	for v := 2; v <= current; v++ {
		if !covered[v] {
			t.Fatalf("docs/policy-changes.md has no section introducing denyfirst-v%d, so either a "+
				"rule set moved without a record or the headings no longer match what this test reads", v)
		}
	}

	for name, text := range section {
		// The section for the name in force may say either: it is written
		// before the tag it names exists, which is the whole reason the stale
		// line this test was written for survived.
		if name == TLSVersion {
			continue
		}
		if strings.Contains(text, "Unreleased") {
			t.Errorf("docs/policy-changes.md still calls %s unreleased. It is not the rule set in "+
				"force (%s is), so it shipped, and a reader asking which upgrade moved their verdicts "+
				"is told it never happened.", name, TLSVersion)
		}
		if !strings.Contains(text, "Released in v") {
			t.Errorf("the %s section names no release. Which upgrade moved the rule set is the first "+
				"thing a reader comparing two reports needs.", name)
		}
	}
}
