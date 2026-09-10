package policy

import (
	"strings"
	"testing"
)

func findingIDs(r WebResult) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func hasFinding(r WebResult, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func noteText(r WebResult) string {
	var b strings.Builder
	for _, n := range r.Notes {
		b.WriteString(n.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// What a browser rejects is graded, because the site does not have the cookie
// it believes it has.
//
// Each of these is what happens next rather than an opinion about
// configuration, and each is invisible from the server: the response looks
// exactly as intended, and the failure appears somewhere else entirely.
func TestACookieABrowserWillNotStoreIsGraded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cookie CookieFacts
		want   string
	}{
		{
			"a host prefix without Path=/",
			CookieFacts{Name: "__Host-sid", HostPrefix: true, Secure: true, Path: "/app", OverTLS: true},
			"cookie.host-prefix-broken",
		},
		{
			"a host prefix carrying a Domain",
			CookieFacts{Name: "__Host-sid", HostPrefix: true, Secure: true, Path: "/", DomainSet: true, OverTLS: true},
			"cookie.host-prefix-broken",
		},
		{
			"a host prefix without Secure",
			CookieFacts{Name: "__Host-sid", HostPrefix: true, Path: "/", OverTLS: true},
			"cookie.host-prefix-broken",
		},
		{
			"a secure prefix without Secure",
			CookieFacts{Name: "__Secure-sid", SecurePrefix: true, Path: "/", OverTLS: true},
			"cookie.secure-prefix-broken",
		},
		{
			"SameSite=None without Secure",
			CookieFacts{Name: "sid", SameSite: "none", OverTLS: true},
			"cookie.samesite-none-without-secure",
		},
		{
			"no Secure on a cookie set over TLS",
			CookieFacts{Name: "sid", OverTLS: true},
			"cookie.no-secure-over-tls",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeCookies([]CookieFacts{tc.cookie})
			if !hasFinding(got, tc.want) {
				t.Errorf("got %v, want a %s finding", findingIDs(got), tc.want)
			}
		})
	}
}

// A cookie a browser stores exactly as the site asked is not graded.
//
// R6: correct configuration is not penalised. A site that has done everything
// the specification asks must come back with nothing against it, or the report
// teaches its reader to ignore it.
func TestACorrectlySetCookieIsNotGraded(t *testing.T) {
	got := GradeCookies([]CookieFacts{{
		Name:       "__Host-sid",
		HostPrefix: true,
		Secure:     true,
		HTTPOnly:   true,
		SameSite:   "strict",
		Path:       "/",
		OverTLS:    true,
	}})

	if len(got.Findings) != 0 {
		t.Errorf("a correctly set cookie produced %v", findingIDs(got))
	}
	if got.Verdict == Insecure || got.Verdict == Weak {
		t.Errorf("a correctly set cookie was graded %q", got.Verdict)
	}
}

// Advice is not a rule, and this is the line R21 draws.
//
// Every one of these is something a reasonable person recommends and no
// document requires. Grading them would be this project inventing a threshold
// nobody can argue with — which means nobody can correct it either, and it
// survives into a report telling somebody their correct decision is a fault.
//
// They are reported instead, because a reader still wants to know.
func TestAdviceIsReportedAndNotGraded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cookie  CookieFacts
		mention string
	}{
		{
			// A CSRF token, a locale, a consent flag and a feature switch are
			// all cookies a page is meant to read. This check does not read
			// cookie values and so cannot tell which it is looking at.
			"a cookie readable by script",
			CookieFacts{Name: "locale", Secure: true, SameSite: "lax", OverTLS: true},
			"HttpOnly",
		},
		{
			// Browsers now treat an absent SameSite as Lax. That is a
			// property of the browser rather than of this server.
			"a cookie with no SameSite",
			CookieFacts{Name: "sid", Secure: true, HTTPOnly: true, OverTLS: true},
			"SameSite",
		},
		{
			// Widening a cookie to a domain is often deliberate.
			"a cookie scoped to a domain",
			CookieFacts{Name: "sid", Secure: true, HTTPOnly: true, SameSite: "lax", DomainSet: true, OverTLS: true},
			"Domain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeCookies([]CookieFacts{tc.cookie})

			if len(got.Findings) != 0 {
				t.Errorf("%s was graded %v; no document sets that line", tc.name, findingIDs(got))
			}
			if !strings.Contains(noteText(got), tc.mention) {
				t.Errorf("%s was neither graded nor reported, so a reader is told nothing:\n%s",
					tc.name, noteText(got))
			}
		})
	}
}

// A cookie set on a plaintext response is not charged twice.
//
// It was already in the clear before any attribute could have helped, and that
// is the reach finding. Reporting it here as well would present one mistake as
// two, which is the same argument the certificate rules make about an
// incomplete chain.
func TestACookieSetOverPlaintextIsNotChargedForMissingSecure(t *testing.T) {
	got := GradeCookies([]CookieFacts{{Name: "sid", OverTLS: false}})

	if hasFinding(got, "cookie.no-secure-over-tls") {
		t.Error("a cookie set over plaintext was charged for missing Secure; the transport is the " +
			"finding, and charging both reports one mistake as two")
	}
}

// Nothing set means nothing said.
//
// A site with no cookies has no cookie findings and no cookie observations —
// not a clean bill of health for something that was never there (R4).
func TestNoCookiesProducesNothing(t *testing.T) {
	got := GradeCookies(nil)

	if len(got.Findings) != 0 || len(got.Notes) != 0 {
		t.Errorf("a site setting no cookies produced %v and %d notes", findingIDs(got), len(got.Notes))
	}
	if got.Verdict != "" {
		t.Errorf("a site setting no cookies was graded %q", got.Verdict)
	}
}

// Many cookies with one fault are one finding.
//
// A site setting nine cookies without Secure would otherwise produce nine
// identical entries, and a report that says one thing nine times is a report a
// reader stops at.
func TestOneFaultAcrossManyCookiesIsOneFinding(t *testing.T) {
	var many []CookieFacts
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		many = append(many, CookieFacts{Name: name, OverTLS: true})
	}

	got := GradeCookies(many)

	count := 0
	for _, f := range got.Findings {
		if f.RuleID == "cookie.no-secure-over-tls" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("five cookies with one fault produced %d findings, want 1", count)
	}
	if !strings.Contains(got.Findings[0].Rationale, "5 cookies") {
		t.Errorf("the finding does not say how many cookies it covers: %s", got.Findings[0].Rationale)
	}
}

// Every cookie finding cites a document and names its rule set.
//
// R2 and R22 together: a verdict rests on something a reader can open, and it
// says which rules produced it.
func TestEveryCookieFindingCitesSomethingAndNamesItsRuleSet(t *testing.T) {
	got := GradeCookies([]CookieFacts{
		{Name: "__Host-a", HostPrefix: true, Path: "/x", Secure: true, OverTLS: true},
		{Name: "b", SameSite: "none", OverTLS: true},
	})

	if len(got.Findings) == 0 {
		t.Fatal("no findings to check")
	}
	for _, f := range got.Findings {
		if len(f.References) == 0 {
			t.Errorf("%s cites nothing, so a reader cannot check it", f.RuleID)
		}
		if f.Policy != WebVersion {
			t.Errorf("%s names rule set %q, want %q", f.RuleID, f.Policy, WebVersion)
		}
		if f.Rationale == "" || f.Title == "" {
			t.Errorf("%s has no title or no rationale", f.RuleID)
		}
	}
}

// A cookie name reaches a report as text and nothing else.
//
// Names are chosen by the scanned server. Nothing here formats one into
// anything that executes it, and the page builds every node with textContent —
// but the sentence still has to carry the name through unchanged so a reader
// can find the cookie it is about.
func TestACookieNameIsCarriedThroughAsText(t *testing.T) {
	got := GradeCookies([]CookieFacts{{Name: "<script>alert(1)</script>", OverTLS: true}})

	if len(got.Findings) == 0 {
		t.Fatal("no finding produced")
	}
	if !strings.Contains(got.Findings[0].Rationale, "<script>alert(1)</script>") {
		t.Error("the cookie name was altered on its way into the report, so a reader cannot match it " +
			"against what their server sent")
	}
}
