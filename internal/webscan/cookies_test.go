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
