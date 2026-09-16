package policy

import (
	"strings"
	"testing"
)

// A header that repeats a directive is not a policy.
//
// RFC 6797 §6.1 allows each directive once, and a browser ignores a header that
// breaks the grammar. The 2026-09-16 audit (A13) saw "max-age=31536000;
// max-age=0" read as a year and graded strong.
func TestARepeatedDirectiveMakesTheHeaderNothing(t *testing.T) {
	for _, v := range []string{
		"max-age=31536000; max-age=0",
		"max-age=31536000; MAX-AGE=31536000",
		"max-age=31536000; includeSubDomains; includesubdomains",
		"max-age=31536000; preload; preload",
	} {
		if p := ParseHSTS(v); p.Parsed {
			t.Errorf("%q parsed as %+v", v, p)
		}
		if got := GradeHSTS([]string{v}, nil, true); got.Verdict == Strong {
			t.Errorf("%q graded strong", v)
		}
	}
	for _, v := range []string{"max-age=31536000", "max-age=31536000; includeSubDomains; preload", "max-age=31536000;"} {
		if p := ParseHSTS(v); !p.Parsed {
			t.Errorf("%q, a valid header, did not parse", v)
		}
	}
}

// A policy without frame-ancestors, or one declared in markup, is not framing
// protection, and the missing X-Frame-Options is said. The 2026-09-16 audit
// (A16) saw any policy at all hide it.
func TestAPolicyWithoutFrameAncestorsDoesNotHideMissingFramingProtection(t *testing.T) {
	said := func(f HeaderFacts) bool {
		for _, n := range GradeHeaders(f).Notes {
			if strings.Contains(n.Text, "X-Frame-Options") {
				return true
			}
		}
		return false
	}
	for name, f := range map[string]HeaderFacts{
		"a meta policy": {Answered: true, MarkupRead: true, MetaCSP: true, Present: map[string]bool{}},
		"a header policy without the directive": {Answered: true,
			Present: map[string]bool{"Content-Security-Policy": true}},
	} {
		if !said(f) {
			t.Errorf("%s: the missing X-Frame-Options is not said", name)
		}
	}
	withDirective := HeaderFacts{Answered: true, FrameAncestors: true,
		Present: map[string]bool{"Content-Security-Policy": true}}
	if said(withDirective) {
		t.Error("a site sending frame-ancestors is told it lacks X-Frame-Options")
	}
}

// An empty directive is in the grammar, and two of them are not a repeat.
func TestEmptyDirectivesAreNotRepeats(t *testing.T) {
	for _, v := range []string{"max-age=31536000;;", "; max-age=31536000 ;; includeSubDomains ;"} {
		if p := ParseHSTS(v); !p.Parsed {
			t.Errorf("%q, a valid header with empty directives, did not parse", v)
		}
	}
}

// A chain that went further than it was followed is not graded as ending there,
// on either side, and is not called sound.
func TestAnUnfollowedChainIsNeitherGradedNorSound(t *testing.T) {
	upgraded := []WebHop{{Answered: true, Status: 301}, {TLS: true, Answered: true, Status: 200}}
	secure := []WebHop{{TLS: true, Answered: true, Status: 200}}

	plainAway := []WebHop{{Answered: true, Status: 302, Unfollowed: true}}
	got := GradeReach(secure, plainAway)
	for _, f := range got.Findings {
		if f.RuleID == "reach.never-reaches-tls" {
			t.Error("a plaintext redirect this scan did not follow was graded as never reaching TLS")
		}
	}
	if got.Verdict == Strong {
		t.Error("a site whose plaintext redirect was not followed is strong")
	}
	if !strings.Contains(strings.Join(Texts(got.Notes), " "), "did not follow") {
		t.Errorf("the unfollowed plaintext redirect is not said: %v", Texts(got.Notes))
	}

	secureAway := []WebHop{{TLS: true, Answered: true, Status: 301, Unfollowed: true}}
	got = GradeReach(secureAway, upgraded)
	if got.Verdict == Strong {
		t.Error("a site whose secure redirect was not followed is strong")
	}
	if !strings.Contains(strings.Join(Texts(got.Notes), " "), "secure address redirects somewhere") {
		t.Errorf("the unfollowed secure redirect is not said: %v", Texts(got.Notes))
	}

	// Followed to their ends, the same shapes grade as they always did.
	if got := GradeReach(secure, upgraded); got.Verdict != Strong {
		t.Errorf("a site reached correctly is %q", got.Verdict)
	}
	stuck := []WebHop{{Answered: true, Status: 302}}
	found := false
	for _, f := range GradeReach(secure, stuck).Findings {
		found = found || f.RuleID == "reach.never-reaches-tls"
	}
	if !found {
		t.Error("a plaintext redirect that ended on plaintext is not graded")
	}
}
