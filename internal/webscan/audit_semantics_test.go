package webscan

import (
	"testing"

	"github.com/denyfirst/porch/internal/markup"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/webprobe"
)

// Another host's policy is not this host's.
//
// example.com redirecting to www.example.com, which sends the header, leaves a
// browser with a policy for www and none for example.com. The 2026-09-16 audit
// (A14) found the other host's policy graded strong for the first.
func TestAPolicyFromAnotherHostIsNotThisHostsPolicy(t *testing.T) {
	redirect := webprobe.Hop{URL: address(true, "a.example.test"), TLS: true, Status: 302,
		Headers: map[string][]string{"Location": {"https://b.example.test/"}}}
	landing := webprobe.Hop{URL: address(true, "b.example.test"), TLS: true, Status: 200,
		Headers: hsts("max-age=31536000")}

	if got := securePolicy(chain(redirect, landing), "a.example.test"); got != nil {
		t.Errorf("a.example.test was given b.example.test's policy %v", got)
	}
	if got := securePolicy(chain(redirect, landing), "B.Example.Test."); len(got) != 1 {
		t.Errorf("b.example.test's own policy was not found under another spelling of its name: %v", got)
	}

	graded := Grade(&webprobe.Report{Host: "a.example.test", Secure: chain(redirect, landing)})
	absent := false
	for _, f := range graded.Findings {
		absent = absent || f.RuleID == "hsts.absent"
	}
	if !absent {
		t.Errorf("a host that sends no policy of its own is not said to have none: %v", graded.Findings)
	}

	// Its own policy on its own redirect is its own.
	own := redirect
	own.Headers = map[string][]string{"Location": {"https://b.example.test/"}, hstsHeader: {"max-age=31536000"}}
	if got := securePolicy(chain(own, landing), "a.example.test"); len(got) != 1 {
		t.Errorf("a.example.test's own policy on its redirect was not found: %v", got)
	}
}

// A redirect this scan did not follow is not a destination.
//
// The 2026-09-16 audit (A15): a plaintext redirect whose target the deployment
// may not reach was graded as never reaching TLS. Where it goes was not measured.
func TestAnUnfollowedRedirectIsNotADestination(t *testing.T) {
	secure := chain(hop(true, 200, hsts("max-age=31536000")))
	plain := &webprobe.Chain{
		Hops: []webprobe.Hop{{URL: address(false, "example.test"), Status: 302,
			Headers: map[string][]string{"Location": {"https://other.test/"}}}},
		Stopped:    "not a host this deployment may reach",
		Unfollowed: true,
	}
	got := Grade(&webprobe.Report{Host: "example.test", Secure: secure, Plain: plain})
	for _, f := range got.Findings {
		if f.RuleID == "reach.never-reaches-tls" {
			t.Error("a redirect this scan did not follow was graded as never reaching TLS")
		}
	}
	if got.Verdict == policy.Strong {
		t.Error("a site whose plaintext redirect was not followed was called strong")
	}

	// Followed to its end on plaintext, the same redirect is the finding.
	stuck := &webprobe.Chain{Hops: []webprobe.Hop{{URL: address(false, "example.test"), Status: 302}}}
	got = Grade(&webprobe.Report{Host: "example.test", Secure: secure, Plain: stuck})
	found := false
	for _, f := range got.Findings {
		found = found || f.RuleID == "reach.never-reaches-tls"
	}
	if !found {
		t.Error("a plaintext redirect that ends on plaintext is no longer graded")
	}

	// A secure redirect that was not followed is not strong either.
	away := &webprobe.Chain{
		Hops: []webprobe.Hop{{URL: address(true, "example.test"), TLS: true, Status: 301,
			Headers: map[string][]string{"Location": {"https://other.test/"}}}},
		Unfollowed: true,
	}
	upgraded := chain(webprobe.Hop{URL: address(false, "example.test"), Status: 301,
		Headers: map[string][]string{"Location": {"https://example.test/"}}},
		hop(true, 301, nil))
	if got := policy.GradeReach(hops(away), hops(upgraded)); got.Verdict == policy.Strong {
		t.Error("a secure address whose redirect was not followed was called strong")
	}

	// A chain cut by the redirect limit is unfollowed; one that ended by itself
	// is not.
	if hs := hops(&webprobe.Chain{Hops: []webprobe.Hop{{Status: 302}}, Truncated: true}); !hs[len(hs)-1].Unfollowed {
		t.Error("a chain cut by the redirect limit is not marked unfollowed")
	}
	if hs := hops(&webprobe.Chain{Hops: []webprobe.Hop{{Status: 302}}}); hs[len(hs)-1].Unfollowed {
		t.Error("a chain that ended by itself is marked unfollowed")
	}
}

// Framing protection is the frame-ancestors directive in an enforcing header.
func TestOnlyFrameAncestorsInAHeaderSupersedesXFrameOptions(t *testing.T) {
	for name, tc := range map[string]struct {
		values []string
		want   bool
	}{
		"frame-ancestors":           {[]string{"default-src 'self'; frame-ancestors 'none'"}, true},
		"case and spacing":          {[]string{"  FRAME-ANCESTORS 'self'"}, true},
		"in a second header":        {[]string{"default-src 'self'", "frame-ancestors 'none'"}, true},
		"a policy without it":       {[]string{"default-src 'self'"}, false},
		"a name that only contains": {[]string{"x-frame-ancestors-y 'none'"}, false},
		"nothing":                   {nil, false},
	} {
		if got := framesDeclared(tc.values); got != tc.want {
			t.Errorf("%s: framesDeclared = %v, want %v", name, got, tc.want)
		}
	}

	// Carried from the response the visitor lands on.
	facts := headerFacts(chain(webprobe.Hop{URL: address(true, "example.test"), TLS: true, Status: 200,
		Headers: map[string][]string{"Content-Security-Policy": {"frame-ancestors 'none'"}}}))
	if !facts.FrameAncestors {
		t.Error("the landing response's frame-ancestors did not reach the header facts")
	}
}

// A report-only policy enforces nothing, frame-ancestors included.
func TestAReportOnlyFrameAncestorsIsNotFramingProtection(t *testing.T) {
	facts := headerFacts(chain(webprobe.Hop{URL: address(true, "example.test"), TLS: true, Status: 200,
		Headers: map[string][]string{"Content-Security-Policy-Report-Only": {"frame-ancestors 'none'"}}}))
	if facts.FrameAncestors {
		t.Error("a report-only frame-ancestors was taken as framing protection")
	}
}

// A page whose read stopped early reaches the grading as one (audit A17).
func TestAnIncompletePageReachesTheGrading(t *testing.T) {
	page := func(incomplete bool) *webprobe.Chain {
		return chain(webprobe.Hop{URL: address(true, "example.test"), TLS: true, Status: 200,
			Markup: &markup.Facts{Read: true, Incomplete: incomplete}})
	}
	if !contentFacts(page(true)).Incomplete {
		t.Error("an incomplete read was not carried to the content facts")
	}
	if contentFacts(page(false)).Incomplete {
		t.Error("a whole page was carried as incomplete")
	}
}
