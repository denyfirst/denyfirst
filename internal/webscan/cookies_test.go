package webscan

import (
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// The cookie rules reach a report.
//
// Written because a sabotage that unhooked them from Grade escaped every test
// there was: the rules were covered in isolation and the wiring was not, which
// is a rule set that is correct and does nothing. It is the same shape as a
// guard placed where nothing calls it.
func TestTheCookieRulesReachAGradedReport(t *testing.T) {
	report := &webprobe.Report{
		Host: "example.test",
		Secure: &webprobe.Chain{Hops: []webprobe.Hop{{
			URL:    "https://example.test:443/",
			TLS:    true,
			Status: 200,
			Cookies: []webprobe.Cookie{
				{Name: "__Host-sid", HostPrefix: true, Secure: true, Path: "/app"},
			},
		}}},
	}

	got := Grade(report)

	var ids []string
	for _, f := range got.Findings {
		ids = append(ids, f.RuleID)
	}
	found := false
	for _, id := range ids {
		if id == "cookie.host-prefix-broken" {
			found = true
		}
	}
	if !found {
		t.Errorf("a cookie a browser rejects produced findings %v; the rules are not wired to the scan", ids)
	}
}

// A cookie set on a hop that failed is not a cookie.
//
// A hop with an error carries no response and no headers. Reading one as a
// response that set nothing would be the same mistake R23 names for the policy
// header: a connection that was refused says nothing about what a server sends.
func TestACookieIsNotReadFromAHopThatFailed(t *testing.T) {
	report := &webprobe.Report{
		Host: "example.test",
		Secure: &webprobe.Chain{Hops: []webprobe.Hop{{
			URL: "https://example.test:443/",
			TLS: true,
			Err: "the connection was refused",
		}}},
	}

	if got := cookieFacts(report); len(got) != 0 {
		t.Errorf("a failed hop produced %d cookies", len(got))
	}
}

// A cookie is tagged with the transport of the response that set it.
//
// That one boolean decides what a missing Secure attribute means, and getting
// it the wrong way round either charges a plaintext site twice or lets a
// secure one carry a cookie that travels in the clear.
func TestACookieCarriesTheTransportItWasSetOn(t *testing.T) {
	report := &webprobe.Report{
		Host: "example.test",
		Secure: &webprobe.Chain{Hops: []webprobe.Hop{{
			URL: "https://example.test:443/", TLS: true, Status: 200,
			Cookies: []webprobe.Cookie{{Name: "secure-hop"}},
		}}},
		Plain: &webprobe.Chain{Hops: []webprobe.Hop{{
			URL: "http://example.test:80/", TLS: false, Status: 200,
			Cookies: []webprobe.Cookie{{Name: "plain-hop"}},
		}}},
	}

	for _, c := range cookieFacts(report) {
		want := c.Name == "secure-hop"
		if c.OverTLS != want {
			t.Errorf("%s was tagged OverTLS=%v, want %v", c.Name, c.OverTLS, want)
		}
	}

	// And the consequence of that tag, through the rules.
	graded := policy.GradeCookies(cookieFacts(report))
	names := ""
	for _, f := range graded.Findings {
		if f.RuleID == "cookie.no-secure-over-tls" {
			names = f.Rationale
		}
	}
	if !strings.Contains(names, "secure-hop") {
		t.Error("the cookie set over TLS was not charged for missing Secure")
	}
	if strings.Contains(names, "plain-hop") {
		t.Error("the cookie set over plaintext was charged for missing Secure; the transport is the finding")
	}
}

// The header rules reach a report too.
//
// The same gap the cookie rules had, found the same way: unhooking them from
// Grade broke nothing, because the rules were covered in isolation and the
// wiring was not.
func TestTheHeaderRulesReachAGradedReport(t *testing.T) {
	report := &webprobe.Report{
		Host: "example.test",
		Secure: &webprobe.Chain{Hops: []webprobe.Hop{{
			URL: "https://example.test:443/", TLS: true, Status: 200,
			Headers: map[string][]string{
				"Access-Control-Allow-Origin":      {"*"},
				"Access-Control-Allow-Credentials": {"true"},
			},
		}}},
	}

	got := Grade(report)

	var ids []string
	for _, f := range got.Findings {
		ids = append(ids, f.RuleID)
	}
	found := false
	for _, id := range ids {
		if id == "headers.cors-wildcard-with-credentials" {
			found = true
		}
	}
	if !found {
		t.Errorf("a response whose CORS headers a browser refuses produced findings %v; "+
			"the rules are not wired to the scan", ids)
	}
	if !strings.Contains(noteTextOf(got), "headers a site can send") {
		t.Error("the reported header list did not reach the report")
	}
}

// The headers read are the ones on the response a visitor lands on.
//
// A different choice from the one securePolicy makes, and the difference
// matters: Strict-Transport-Security persists in the browser, so the value
// that counts is the last carried by any hop over TLS. These headers apply to
// the response that carries them and nothing else, so the one that counts is
// the response whose content the visitor actually receives.
func TestTheHeadersReadAreTheOnesOnTheResponseAVisitorLandsOn(t *testing.T) {
	report := &webprobe.Report{
		Host: "example.test",
		Secure: &webprobe.Chain{Hops: []webprobe.Hop{
			{
				URL: "https://example.test:443/", TLS: true, Status: 301,
				Headers: map[string][]string{
					"Location":                {"https://www.example.test/"},
					"Content-Security-Policy": {"default-src 'self'"},
				},
			},
			{
				URL: "https://www.example.test/", TLS: true, Status: 200,
				Headers: map[string][]string{"Referrer-Policy": {"no-referrer"}},
			},
		}},
	}

	facts := headerFacts(report.Secure)
	if !facts.Present["Referrer-Policy"] {
		t.Error("the response a visitor lands on was not the one read")
	}
	if facts.Present["Content-Security-Policy"] {
		t.Error("a policy carried by a redirect was read as though it applied to the page; " +
			"these headers apply to the response that carries them and to nothing else")
	}
}

func noteTextOf(r *Result) string {
	var b strings.Builder
	for _, n := range r.Notes {
		b.WriteString(n.Text)
		b.WriteString("\n")
	}
	return b.String()
}
