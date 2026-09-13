package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// The script reads the field names the API actually sends.
//
// R16 says one result, two renderers, one set of facts. This is the seam where
// that is easiest to break without anything failing: the Go side marshals a
// struct, the script reads properties off the parsed object, and nothing
// connects the two but a matching spelling in a file nobody is diffing
// together.
//
// It broke on the first try. policy.MailFacts carried no JSON tags at all, so
// it went out as "SPFRecords" while every other observed struct in this project
// sends lowercase — and the console, reading facts.spfRecords, got undefined
// for all of it. The visible result was the worst available: a domain whose SPF
// lookup had failed was drawn as "SPF none published", which is a claim about
// the domain rather than about the scan, and is precisely the distinction R4
// exists for.
//
// A browser is what found it. This is so a test does.
func TestTheConsoleReadsTheFieldNamesTheAPISends(t *testing.T) {
	// A value with every field set, so nothing is omitted on the way out.
	raw, err := json.Marshal(policy.MailFacts{
		SPFRecords: 1, SPFAll: "-", SPFLookups: 4,
		SPFLookupLimit: true, SPFVoidLimit: true, SPFVoidLookups: 3,
		SPFUsesPTR: true, SPFIncludes: []string{"spf.example"}, SPFReason: "unreadable",
		DMARCRecords: 1, DMARCPolicy: "reject", DMARCPercent: 100,
		DMARCReporting: true, DMARCReason: "unreadable",
		TLSReporting: true,
		MXRead:       true, MXHosts: []string{"mx.example"}, MXReason: "unreadable",
		MTASTSRecords: 1, MTASTSPolicyRead: true, MTASTSPolicyReason: "unreadable",
		MTASTSMode: "enforce", MTASTSMaxAge: 604800,
		MTASTSPolicyMX: []string{"mx.example"}, MTASTSUncovered: []string{"mx2.example"},
	})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}

	source := script(t)

	// Every property the script reads off the observations is one the API
	// sends. A name the script asks for and the API does not send reads as
	// undefined, which in JavaScript is silently falsy — so the failure is a
	// wrong sentence rather than an error.
	for _, field := range []string{
		"spfRecords", "spfAll", "spfLookups", "spfLookupLimit", "spfReason",
		"dmarcRecords", "dmarcPolicy", "dmarcPercent", "dmarcReason",
		"tlsReporting",

		// The MTA-STS group, added when the policy file became readable. Four
		// of these decide which of four sentences the row draws, and a name
		// misspelled on either side of the seam picks the wrong one silently:
		// mtaStsPolicyRead read as undefined draws "the policy was not read"
		// over a policy that was, which is the reassuring failure rather than
		// the loud one.
		"mxHosts", "mtaStsRecords", "mtaStsPolicyRead", "mtaStsPolicyReason",
		"mtaStsMode", "mtaStsUncovered",
	} {
		if !strings.Contains(source, "facts."+field) {
			t.Errorf("the console does not read facts.%s; this test is naming a field nobody uses", field)
			continue
		}
		if _, ok := sent[field]; !ok {
			t.Errorf("the console reads facts.%s and the API sends no such field. In JavaScript "+
				"that is undefined, which is falsy, so the page draws a sentence rather than "+
				"raising anything.", field)
		}
	}

	// And nothing goes out under a Go field name.
	//
	// The shape of the original defect: a struct with no tags marshals its
	// identifiers, which are capitalised, and every other observed struct here
	// sends lowercase. One of them being different is one page reading the
	// wrong object.
	for name := range sent {
		if name == "" {
			continue
		}
		if c := name[0]; c >= 'A' && c <= 'Z' {
			t.Errorf("MailFacts sends %q, which is a Go identifier rather than a JSON name. "+
				"Every other observed struct in this project sends lowercase.", name)
		}
	}
}
