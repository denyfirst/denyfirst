package policy

import (
	"os"
	"regexp"
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

	if !strings.Contains(string(body), Version) {
		t.Errorf("docs/policy-changes.md does not mention %q. The rules moved and the page describing "+
			"what moved did not, so a reader comparing two reports is told the wrong thing.", Version)
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

	quoted := regexp.MustCompile(`"((?:cipher|cert|version)\.[a-z0-9-]+)"`)
	for _, file := range []string{"policy.go", "cert.go", "issuance.go", "staple.go", "transparency.go"} {
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
			if !strings.HasPrefix(id, "cipher.") && !strings.HasPrefix(id, "cert.") {
				continue
			}
			if !known[id] {
				t.Errorf("docs/policy-changes.md names %q and no rule has that identifier", id)
			}
		}
	}
}
