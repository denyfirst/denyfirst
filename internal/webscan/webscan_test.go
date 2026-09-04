package webscan

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

func hop(tls bool, status int, headers map[string][]string) webprobe.Hop {
	return webprobe.Hop{TLS: tls, Status: status, Headers: headers}
}

func failed(tls bool) webprobe.Hop {
	return webprobe.Hop{TLS: tls, Err: "connection refused"}
}

func hsts(value string) map[string][]string {
	return map[string][]string{hstsHeader: {value}}
}

func chain(hops ...webprobe.Hop) *webprobe.Chain { return &webprobe.Chain{Hops: hops} }

func TestThePolicyReadIsTheOneABrowserWouldHold(t *testing.T) {
	// A browser applies Strict-Transport-Security from every response that
	// arrives over a secure transport, so what it keeps is the last one it
	// was given that way. Reading the last hop, or the first, describes a
	// policy nobody holds.
	for _, tc := range []struct {
		name  string
		chain *webprobe.Chain
		want  []string
	}{
		{
			name:  "one secure response",
			chain: chain(hop(true, 200, hsts("max-age=1"))),
			want:  []string{"max-age=1"},
		},
		{
			name:  "the later secure response replaces the earlier",
			chain: chain(hop(true, 301, hsts("max-age=1")), hop(true, 200, hsts("max-age=2"))),
			want:  []string{"max-age=2"},
		},
		{
			// A redirect that sets the policy and a landing page that does
			// not: the browser still holds the policy.
			name:  "a policy set on a redirect and not on the page",
			chain: chain(hop(true, 301, hsts("max-age=1")), hop(true, 200, nil)),
			want:  []string{"max-age=1"},
		},
		{
			// The downgrade case. The plaintext hop is where the chain ends,
			// and a browser will not read a policy from it.
			name:  "a chain that ends on plaintext",
			chain: chain(hop(true, 302, hsts("max-age=1")), hop(false, 200, hsts("max-age=999"))),
			want:  []string{"max-age=1"},
		},
		{
			name:  "no policy anywhere",
			chain: chain(hop(true, 200, nil)),
			want:  nil,
		},
		{
			// A refused connection is not a response with no headers.
			name:  "the last hop failed",
			chain: chain(hop(true, 301, hsts("max-age=1")), failed(true)),
			want:  []string{"max-age=1"},
		},
		{
			name:  "nothing answered at all",
			chain: chain(failed(true)),
			want:  nil,
		},
		{name: "no chain", chain: nil, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := securePolicy(tc.chain)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("securePolicy = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPolicySentOverPlaintextIsFoundSoItCanBeReported(t *testing.T) {
	// Sending the header only where a browser discards it is a common
	// arrangement, and one nothing else in a report would show: the site is
	// configured and unprotected at the same time.
	got := plaintextPolicy(chain(hop(false, 200, hsts("max-age=63072000"))))
	if len(got) != 1 {
		t.Fatalf("plaintextPolicy = %v, want the header", got)
	}
	if v := plaintextPolicy(chain(hop(true, 200, hsts("max-age=1")))); v != nil {
		t.Errorf("a secure hop was read as plaintext: %v", v)
	}
	if v := plaintextPolicy(chain(failed(false))); v != nil {
		t.Errorf("a failed hop produced headers: %v", v)
	}
}

func TestAFailedHopIsNotAResponseWithNoHeaders(t *testing.T) {
	// The difference decides a verdict: a host that answers 200 in the clear
	// is insecure, and a host with nothing on port 80 is the safest
	// arrangement there is.
	got := hops(chain(failed(false)))
	if len(got) != 1 || got[0].Answered {
		t.Fatalf("hops = %+v, want one hop that did not answer", got)
	}
	if got := hops(chain(hop(false, 200, nil))); !got[0].Answered {
		t.Fatalf("a 200 was recorded as no answer: %+v", got)
	}
	if hops(nil) != nil {
		t.Error("a missing chain produced hops")
	}
}

// prober is a webprobe.Prober replacement. The scanner takes the concrete
// type, so the seam is the probe's own Dial: a test serves both chains from
// one handler and never leaves the machine.
func TestAWholeScanIsGradedAndCarriesItsEvidence(t *testing.T) {
	// The arrangement this check exists to name: TLS answers, port 80 serves
	// the same site in the clear, and no policy is declared anywhere.
	observed := &webprobe.Report{
		Host:   "example.test",
		Secure: chain(hop(true, 200, nil)),
		Plain:  chain(hop(false, 200, nil)),
	}

	out := Grade(observed)

	if out.Verdict != policy.Insecure {
		t.Errorf("verdict %q, want insecure", out.Verdict)
	}
	if !hasRule(out, "reach.plaintext-served") {
		t.Errorf("the plaintext page was not reported: %v", rules(out))
	}
	if !hasRule(out, "hsts.absent") {
		t.Errorf("the missing policy was not reported: %v", rules(out))
	}
	if out.Policy != policy.WebVersion {
		t.Errorf("Policy = %q, want %q", out.Policy, policy.WebVersion)
	}
	if out.Observed == nil {
		t.Error("the report carries no evidence, so a reader cannot check the verdict")
	}
}

func TestACorrectlyReachedSiteIsNotGraded(t *testing.T) {
	observed := &webprobe.Report{
		Host:   "example.test",
		Secure: chain(hop(true, 200, hsts("max-age=63072000; includeSubDomains"))),
		Plain:  chain(hop(false, http.StatusMovedPermanently, nil), hop(true, 200, nil)),
	}
	out := Grade(observed)
	if len(out.Findings) != 0 {
		t.Fatalf("a correct arrangement was graded: %v", rules(out))
	}
	if out.Verdict != policy.Ungraded {
		t.Errorf("verdict %q, want ungraded", out.Verdict)
	}
	// And it still says what it could not establish.
	if len(out.Notes) == 0 {
		t.Error("no notes at all, so the report claims more than it measured")
	}
}

func TestEveryReportCarriesTheLimitsOfTheMethod(t *testing.T) {
	// Declared in one place. A report that wrote its own would drift from the
	// page explaining them, and the sentence a reader is asked to trust would
	// exist in two versions.
	out := Grade(&webprobe.Report{Secure: chain(hop(true, 200, hsts("max-age=63072000"))), Plain: chain(failed(false))})

	want := policy.WebStandingLimits()
	if len(want) == 0 {
		t.Fatal("the web check declares no limits")
	}
	for _, l := range want {
		found := false
		for _, n := range out.Notes {
			if n.Kind == policy.KindStanding && n.Text == l.Text {
				found = true
			}
		}
		if !found {
			t.Errorf("the limit %q is missing from the report", l.ID)
		}
	}
}

func TestNoTLSLimitIsCarriedByAWebReport(t *testing.T) {
	// What a TLS scan cannot establish and what a header check cannot
	// establish are different lists. A report carrying the wrong one tells
	// its reader that cipher suites were considered.
	out := Grade(&webprobe.Report{Secure: chain(hop(true, 200, nil)), Plain: chain(failed(false))})
	for _, n := range out.Notes {
		if policy.IsStandingLimit(n.Text) {
			t.Errorf("a TLS limit reached a web report: %q", n.Text)
		}
	}
}

func TestTheReportSerialisesWithoutItsSecrets(t *testing.T) {
	// The evidence travels with the verdict, and the probe's discipline has
	// to survive the trip: no header this check does not grade, and no cookie
	// value, whatever a caller does with the result.
	observed := &webprobe.Report{
		Host:   "example.test",
		Secure: chain(hop(true, 200, hsts("max-age=1"))),
		Plain:  chain(failed(false)),
	}
	observed.Secure.Hops[0].Cookies = []webprobe.Cookie{{Name: "sid", Secure: true}}

	blob, err := json.Marshal(Grade(observed))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "denyfirst-web-") {
		t.Error("the serialised result does not name its rule set")
	}
	if strings.Contains(string(blob), "\"value\"") {
		t.Error("a cookie value field reached the serialised result")
	}
}

func TestATargetThatIsNotAHostnameIsRefusedBeforeAnythingIsAttempted(t *testing.T) {
	// A refusal is an error and not a report. The difference matters to a
	// caller: a report with no findings reads as a host that is fine.
	s := &Scanner{Prober: &webprobe.Prober{}}
	if _, err := s.Scan(context.Background(), "not a hostname"); err == nil {
		t.Fatal("a target that is not a hostname has to be refused")
	}
}

func TestScanAndGradeAgreeOnTheHost(t *testing.T) {
	// Scan sets the host from what it was asked for, Grade from what the
	// probe reported. They are the same name, and a test that only ever
	// called one of them would not notice if they stopped being.
	observed := &webprobe.Report{Host: "example.test", Secure: chain(hop(true, 200, nil)), Plain: chain(failed(false))}
	if got := Grade(observed).Host; got != "example.test" {
		t.Errorf("Grade set the host to %q", got)
	}
}

func rules(r *Result) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func hasRule(r *Result, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
