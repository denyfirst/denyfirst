package policy

import "fmt"

// The cookie rules, and the line between what is graded and what is reported.
//
// Every cookie a site sets is visible in the response headers, and until now
// this rule set read none of them. What follows grades exactly the cases where
// a browser's own behaviour settles the question, and reports the rest.
//
// R21 is the whole of the distinction and it is easy to get wrong here,
// because there is a large body of advice about cookies and almost none of it
// is a line anybody published. "Set HttpOnly on every cookie" is good advice
// and is not a rule: a CSRF token, a locale, a consent flag and a feature
// switch are all cookies a page is meant to read, and this check cannot tell
// which it is looking at — deliberately, since Cookie has nowhere to hold a
// value. A rule that failed those servers would be this project inventing a
// threshold nobody can argue with, which is the failure R21 exists to name.
//
// What is graded instead is the set of cases where the cookie does not work.
// A browser rejects a __Host- cookie that breaks its prefix, rejects
// SameSite=None without Secure, and sends a cookie without Secure over
// plaintext. Those are not opinions about configuration; they are what happens
// next, and a site that has one of them is usually the last to know, because
// every symptom appears somewhere other than the header.
var (
	rfc6265bis = Reference{
		"RFC 6265bis — Cookies: HTTP State Management Mechanism",
		"https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis",
	}
	owaspSession = Reference{
		"OWASP — Session Management Cheat Sheet",
		"https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
	}
)

// CookieFacts is one Set-Cookie, reduced to what the rules read.
//
// A struct rather than the probe's own type, so that internal/policy keeps its
// one unusual property: it imports nothing of this project's own, and a rule
// can be read without reading a probe.
type CookieFacts struct {
	Name string

	Secure    bool
	HTTPOnly  bool
	SameSite  string
	Path      string
	DomainSet bool

	// HostPrefix and SecurePrefix are the two name prefixes a browser
	// enforces structurally.
	HostPrefix   bool
	SecurePrefix bool

	// OverTLS records whether the response that set this cookie arrived over
	// a secure transport. It decides what a missing Secure attribute means:
	// on a plaintext response the cookie was already in the clear before any
	// attribute could help, and that is the reach finding rather than this
	// one.
	OverTLS bool
}

// GradeCookies reads what a site set, and grades only what a browser settles.
func GradeCookies(cookies []CookieFacts) WebResult {
	var out WebResult
	if len(cookies) == 0 {
		return out
	}

	// Counted rather than repeated. A site setting nine cookies without
	// HttpOnly would otherwise produce nine identical entries, and a report
	// that says one thing nine times is a report a reader stops at.
	var (
		insecure    []string
		brokenHost  []string
		brokenPfx   []string
		sameSiteNon []string
		noHTTPOnly  []string
		noSameSite  []string
		widened     []string
	)

	for _, c := range cookies {
		// ── graded: the browser decides, and it decides against the site ──

		// A cookie set over TLS without Secure is sent again on the next
		// plaintext request to the same host, in the clear, whatever the site
		// does elsewhere. There is no configuration for which that is the
		// intended outcome.
		if c.OverTLS && !c.Secure {
			insecure = append(insecure, c.Name)
		}

		// A __Host- cookie must carry Secure, must set Path=/, and must carry
		// no Domain. A browser that finds any of those wrong does not store
		// the cookie at all.
		if c.HostPrefix && (!c.Secure || c.Path != "/" || c.DomainSet) {
			brokenHost = append(brokenHost, c.Name)
		}

		// A __Secure- cookie must carry Secure, on the same terms.
		if c.SecurePrefix && !c.Secure {
			brokenPfx = append(brokenPfx, c.Name)
		}

		// SameSite=None without Secure is rejected outright.
		if c.SameSite == "none" && !c.Secure {
			sameSiteNon = append(sameSiteNon, c.Name)
		}

		// ── reported: a correct site can look like this ──

		if !c.HTTPOnly {
			noHTTPOnly = append(noHTTPOnly, c.Name)
		}
		if c.SameSite == "" {
			noSameSite = append(noSameSite, c.Name)
		}
		if c.DomainSet && !c.HostPrefix {
			widened = append(widened, c.Name)
		}
	}

	if len(insecure) > 0 {
		out.add(Finding{
			RuleID:  "cookie.no-secure-over-tls",
			Verdict: Insecure,
			Title:   "A cookie set over TLS will also travel in the clear",
			Rationale: fmt.Sprintf("%s set without the Secure attribute on a response that arrived over TLS. "+
				"A browser sends such a cookie on plaintext requests to this host as well, so anyone on the "+
				"path reads it — and the site cannot tell, because the secure request that set it looked "+
				"correct. Secure is what confines a cookie to the transport it was issued on.",
				namedCookies(insecure)),
			References: []Reference{rfc6265bis, owaspSession},
		})
	}

	if len(brokenHost) > 0 {
		out.add(Finding{
			RuleID:  "cookie.host-prefix-broken",
			Verdict: Weak,
			Title:   "A __Host- cookie does not meet the prefix and is discarded",
			Rationale: fmt.Sprintf("%s named with the __Host- prefix without meeting it: the prefix requires "+
				"Secure, Path=/, and no Domain attribute. A browser rejects the cookie entirely rather than "+
				"storing it with weaker scope, so the site is running without a cookie it believes it set, "+
				"and every symptom of that appears somewhere other than this header.",
				namedCookies(brokenHost)),
			References: []Reference{rfc6265bis},
		})
	}

	if len(brokenPfx) > 0 {
		out.add(Finding{
			RuleID:  "cookie.secure-prefix-broken",
			Verdict: Weak,
			Title:   "A __Secure- cookie does not meet the prefix and is discarded",
			Rationale: fmt.Sprintf("%s named with the __Secure- prefix but sent without the Secure attribute. "+
				"The prefix is enforced by the browser, which rejects the cookie rather than storing it, so "+
				"the name claims a guarantee the cookie does not have and the cookie is not there at all.",
				namedCookies(brokenPfx)),
			References: []Reference{rfc6265bis},
		})
	}

	if len(sameSiteNon) > 0 {
		out.add(Finding{
			RuleID:  "cookie.samesite-none-without-secure",
			Verdict: Weak,
			Title:   "SameSite=None without Secure is rejected",
			Rationale: fmt.Sprintf("%s declared SameSite=None without the Secure attribute. Browsers reject "+
				"that combination, so the cookie is not stored: the cross-site behaviour the site asked for "+
				"is not what it gets, and neither is the ordinary behaviour it would have had by saying "+
				"nothing.", namedCookies(sameSiteNon)),
			References: []Reference{rfc6265bis},
		})
	}

	// ── the reported half ──
	//
	// Each of these is a fact about the response with no verdict attached,
	// because a correctly configured site can produce every one of them and a
	// scan cannot tell the difference from outside.

	if len(noHTTPOnly) > 0 {
		out.observe(fmt.Sprintf("%s readable by script, having no HttpOnly attribute. Whether that is a "+
			"fault depends on what the cookie is for: a session identifier should not be reachable from "+
			"script, and a CSRF token, a locale or a feature switch is meant to be. This check does not "+
			"read cookie values and so cannot tell which it is looking at.", namedCookies(noHTTPOnly)))
	}

	if len(noSameSite) > 0 {
		out.observe(fmt.Sprintf("%s sent with no SameSite attribute. Browsers now treat that as Lax, so it "+
			"is not left unconstrained — but that is a property of the browser rather than of this server, "+
			"and an older client applies no restriction at all.", namedCookies(noSameSite)))
	}

	if len(widened) > 0 {
		out.observe(fmt.Sprintf("%s scoped with a Domain attribute, which widens it beyond the host that "+
			"set it to that domain and everything under it. That is often deliberate and is stated here "+
			"because it decides how far a cookie travels.", namedCookies(widened)))
	}

	return out
}

// namedCookies writes a list of cookie names as a sentence subject.
//
// The names are chosen by the scanned server, so they reach a report the same
// way every other value does: as text that is never handed to a parser. Only
// names — Cookie has nowhere to hold a value, which is the point of it.
func namedCookies(names []string) string {
	switch len(names) {
	case 1:
		return "The cookie " + names[0] + " is"
	case 2:
		return "The cookies " + names[0] + " and " + names[1] + " are"
	default:
		return fmt.Sprintf("%d cookies, including %s and %s, are",
			len(names), names[0], names[1])
	}
}
